/*
 * headless_su password store: salted SHA-256 in a root-only file.
 * See password.h.
 */
#define _GNU_SOURCE
#include "password.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

/* ------------------------------------------------------------- SHA-256 */

typedef struct {
    uint32_t h[8];
    uint64_t len;
    unsigned char buf[64];
    size_t buflen;
} sha256_ctx;

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_transform(sha256_ctx *c, const unsigned char *p) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROTR(w[i - 15], 7) ^ ROTR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROTR(w[i - 2], 17) ^ ROTR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3];
    uint32_t e = c->h[4], f = c->h[5], g = c->h[6], h = c->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = cc;
        cc = b;
        b = a;
        a = t1 + t2;
    }
    c->h[0] += a;
    c->h[1] += b;
    c->h[2] += cc;
    c->h[3] += d;
    c->h[4] += e;
    c->h[5] += f;
    c->h[6] += g;
    c->h[7] += h;
}

static void sha256_init(sha256_ctx *c) {
    memset(c, 0, sizeof *c);
    c->h[0] = 0x6a09e667;
    c->h[1] = 0xbb67ae85;
    c->h[2] = 0x3c6ef372;
    c->h[3] = 0xa54ff53a;
    c->h[4] = 0x510e527f;
    c->h[5] = 0x9b05688c;
    c->h[6] = 0x1f83d9ab;
    c->h[7] = 0x5be0cd19;
}

static void sha256_update(sha256_ctx *c, const void *data, size_t len) {
    const unsigned char *p = data;
    c->len += len;
    while (len) {
        size_t take = 64 - c->buflen;
        if (take > len) take = len;
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take;
        p += take;
        len -= take;
        if (c->buflen == 64) {
            sha256_transform(c, c->buf);
            c->buflen = 0;
        }
    }
}

static void sha256_final(sha256_ctx *c, unsigned char out[32]) {
    uint64_t bits = c->len * 8;
    unsigned char pad[72];
    size_t padlen = (c->buflen < 56) ? (56 - c->buflen) : (120 - c->buflen);
    memset(pad, 0, padlen);
    pad[0] = 0x80;
    sha256_update(c, pad, padlen);
    unsigned char lenb[8];
    for (int i = 0; i < 8; i++) lenb[i] = (unsigned char)(bits >> (56 - 8 * i));
    sha256_update(c, lenb, 8);
    for (int i = 0; i < 8; i++) {
        out[i * 4] = (unsigned char)(c->h[i] >> 24);
        out[i * 4 + 1] = (unsigned char)(c->h[i] >> 16);
        out[i * 4 + 2] = (unsigned char)(c->h[i] >> 8);
        out[i * 4 + 3] = (unsigned char)c->h[i];
    }
}

void password_sha256(const void *data, size_t len, unsigned char out[32]) {
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

static void sha256_salted(const unsigned char *salt, size_t saltlen, const char *pw,
                          unsigned char out[32]) {
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, salt, saltlen);
    sha256_update(&c, pw, strlen(pw));
    sha256_final(&c, out);
}

/* ------------------------------------------------------------- helpers */

void password_wipe(void *p, size_t n) {
    volatile unsigned char *v = p;
    while (n--) *v++ = 0;
}

static int cteq(const void *a, const void *b, size_t n) {
    const unsigned char *x = a, *y = b;
    unsigned char d = 0;
    for (size_t i = 0; i < n; i++) d |= (unsigned char)(x[i] ^ y[i]);
    return d == 0;
}

static void bin2hex(const unsigned char *in, size_t n, char *out) {
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2] = h[in[i] >> 4];
        out[i * 2 + 1] = h[in[i] & 15];
    }
    out[n * 2] = '\0';
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decodes exactly 2*max hex chars; returns byte count, or -1 on bad input. */
static int hex2bin(const char *in, unsigned char *out, size_t max) {
    size_t n = strlen(in);
    if (n == 0 || n % 2 || n / 2 > max) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hexval(in[i * 2]), lo = hexval(in[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return (int)(n / 2);
}

static int fill_random(void *buf, size_t n) {
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    unsigned char *p = buf;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (r == 0) break;
        got += (size_t)r;
    }
    close(fd);
    return got == n ? 0 : -1;
}

static int write_all(int fd, const void *buf, size_t n) {
    const char *p = buf;
    while (n) {
        ssize_t r = write(fd, p, n);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += r;
        n -= (size_t)r;
    }
    return 0;
}

/* Make a rename/unlink in the store directory durable across power loss. */
static void sync_dir(void) {
    int fd = open(HEADLESS_SU_PW_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return;
    fsync(fd);
    close(fd);
}

/* --------------------------------------------------------------- store */

int password_verify(const char *pw) {
    if (!pw) return 0;
    FILE *f = fopen(HEADLESS_SU_PW_PATH, "re");
    if (!f) {
        if (errno == ENOENT) /* length first: pw may be shorter than the default */
            return strlen(pw) == sizeof HEADLESS_SU_PW_DEFAULT - 1 &&
                   cteq(pw, HEADLESS_SU_PW_DEFAULT, sizeof HEADLESS_SU_PW_DEFAULT - 1);
        return -1;
    }
    char line[512];
    char *got = fgets(line, sizeof line, f);
    fclose(f);
    if (!got) return -1;

    if (strncmp(line, "v1:", 3) != 0) return -1;
    char *salthex = line + 3;
    char *colon = strchr(salthex, ':');
    if (!colon) return -1;
    *colon = '\0';
    char *hashhex = colon + 1;
    char *nl = strpbrk(hashhex, "\r\n");
    if (nl) *nl = '\0';

    unsigned char salt[32], want[32];
    int slen = hex2bin(salthex, salt, sizeof salt);
    int hlen = hex2bin(hashhex, want, 32);
    if (slen <= 0 || hlen != 32) return -1;

    unsigned char have[32];
    sha256_salted(salt, (size_t)slen, pw, have);
    return cteq(have, want, 32) ? 1 : 0;
}

int password_set(const char *pw) {
    if (!pw || !*pw) {
        errno = EINVAL;
        return -1;
    }
    unsigned char salt[16];
    if (fill_random(salt, sizeof salt) < 0) return -1;

    unsigned char hash[32];
    sha256_salted(salt, sizeof salt, pw, hash);
    char salthex[33], hashhex[65], line[128];
    bin2hex(salt, sizeof salt, salthex);
    bin2hex(hash, sizeof hash, hashhex);
    int n = snprintf(line, sizeof line, "v1:%s:%s\n", salthex, hashhex);
    if (n <= 0 || (size_t)n >= sizeof line) {
        errno = EINVAL;
        return -1;
    }

    mkdir(HEADLESS_SU_PW_DIR, 0700);
    chmod(HEADLESS_SU_PW_DIR, 0700);

    char tmp[PATH_MAX];
    if (snprintf(tmp, sizeof tmp, "%s.tmp", HEADLESS_SU_PW_PATH) >= (int)sizeof tmp) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    if (write_all(fd, line, (size_t)n) < 0 || fsync(fd) < 0) {
        int e = errno;
        close(fd);
        unlink(tmp);
        errno = e;
        return -1;
    }
    close(fd);
    if (rename(tmp, HEADLESS_SU_PW_PATH) < 0) {
        int e = errno;
        unlink(tmp);
        errno = e;
        return -1;
    }
    chmod(HEADLESS_SU_PW_PATH, 0600);
    sync_dir();
    password_wipe(salt, sizeof salt);
    password_wipe(hash, sizeof hash);
    password_wipe(line, sizeof line);
    return 0;
}

int password_clear(void) {
    if (unlink(HEADLESS_SU_PW_PATH) < 0) return errno == ENOENT ? 0 : -1;
    sync_dir();
    return 0;
}

/* Exclusive flock on the store's lock file, released when the returned fd is
 * closed or the process dies. Every su session takes it around a password
 * check (and the failure delay), so guesses are serialized device-wide
 * instead of per connection. */
int password_lock(void) {
    mkdir(HEADLESS_SU_PW_DIR, 0700);
    int fd = open(HEADLESS_SU_PW_LOCK, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    while (flock(fd, LOCK_EX) < 0) {
        if (errno != EINTR) {
            close(fd);
            return -1;
        }
    }
    return fd;
}

/* ------------------------------------------------------------- prompt */

int password_read_line(int fd, char *buf, size_t size) {
    size_t i = 0;
    for (;;) {
        char ch;
        ssize_t n = read(fd, &ch, 1);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) {
            if (i == 0) return -1;
            break;
        }
        if (ch == '\n' || ch == '\r') break;
        if (i + 1 < size) buf[i++] = ch;
    }
    buf[i] = '\0';
    return 0;
}

/* Terminal state while echo is off, so that a signal at the prompt (Ctrl-C,
 * kill) does not leave the user's terminal without echo. */
static int g_echo_fd = -1;
static struct termios g_echo_saved;
static const int g_echo_sigs[] = {SIGINT, SIGQUIT, SIGTERM, SIGHUP};
#define N_ECHO_SIGS (sizeof g_echo_sigs / sizeof *g_echo_sigs)

static void restore_echo_and_die(int sig) {
    tcsetattr(g_echo_fd, TCSAFLUSH, &g_echo_saved);
    ssize_t w = write(g_echo_fd, "\n", 1);
    (void)w;
    signal(sig, SIG_DFL);
    raise(sig); /* delivered with the default action once the handler returns */
}

int read_password(const char *prompt, char *buf, size_t size) {
    if (size) buf[0] = '\0';
    int fd = open("/dev/tty", O_RDWR | O_CLOEXEC);
    int close_fd = fd >= 0;
    if (fd < 0) fd = STDIN_FILENO;

    int tty = isatty(fd);
    struct termios saved;
    struct sigaction old[N_ECHO_SIGS];
    int have_saved = tty && tcgetattr(fd, &saved) == 0;
    if (have_saved) {
        g_echo_fd = fd;
        g_echo_saved = saved;
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = restore_echo_and_die;
        for (size_t i = 0; i < N_ECHO_SIGS; i++) {
            sigaction(g_echo_sigs[i], NULL, &old[i]);
            if (old[i].sa_handler != SIG_IGN) sigaction(g_echo_sigs[i], &sa, NULL);
        }
        struct termios raw = saved;
        raw.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(fd, TCSAFLUSH, &raw);
        if (prompt) write_all(fd, prompt, strlen(prompt));
    }
    int r = password_read_line(fd, buf, size);
    if (have_saved) {
        tcsetattr(fd, TCSAFLUSH, &saved);
        write_all(fd, "\n", 1);
        for (size_t i = 0; i < N_ECHO_SIGS; i++) sigaction(g_echo_sigs[i], &old[i], NULL);
        g_echo_fd = -1;
    }
    if (close_fd) close(fd);
    return r;
}
