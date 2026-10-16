/*
 * headless_su - root daemon + su client for a headless, single-user
 * LineageOS server (Galaxy S8+, dream2lte).
 *
 * Any caller that knows the root password gets root. There is no per-app
 * permission management (no prompts, no allowlist, no manager app); the
 * password is the single gate. It defaults to "root" until 'set_root_pwd'
 * writes a salted SHA-256 hash to /data/misc/headless_su/passwd, after which
 * the default no longer works (see password.c). Password checks are
 * serialized device-wide with a 1 s delay after each failure, a client that
 * does not answer within AUTH_TIMEOUT is dropped, and at most MAX_SESSIONS
 * sessions run at once.
 *
 * Like sudo, a correct password unlocks su for the caller's terminal session
 * for TICKET_TIMEOUT (15 min), renewed by every use: same uid, same
 * controlling terminal, same session (whose leader must be the same process,
 * so a recycled session id does not inherit it). Callers without a terminal
 * always answer the password on stdin and never use or create unlocks.
 * Unlocks live in the daemon's memory only (gone after a reboot or a daemon
 * restart) and die with any password change; 'su -k' drops the caller's own.
 *
 *   su --daemon                               run the daemon (init: sud.rc)
 *   su [options] [-] [user [args...]]         client
 *
 * Options (Magisk-compatible subset):
 *   -c, --command CMD ...     run CMD with "sh -c" (consumes the rest of argv)
 *   -s, --shell SHELL         use SHELL instead of /system/bin/sh
 *   -l, --login, -            login-style environment, start in /
 *   -p, -m, --preserve-environment   accepted; the environment is kept anyway
 *   -M, -mm, --mount-master   run in the global (init) mount namespace
 *   -t, --target PID          run in the mount namespace of PID
 *   -k, --reset-timestamp     forget this session's unlock (alone: only that)
 *   -h, --help   -v, --version   -V
 *
 * How it works: the client connects to the daemon's abstract unix socket and
 * sends path/argv/env/cwd plus its stdin/stdout/stderr (SCM_RIGHTS). The
 * daemon forks a root child in the caller's mount namespace. If any std fd is
 * a terminal, the child gets a fresh pty (job control, /dev/tty) and the
 * daemon relays between the caller's terminal and the pty while the client
 * keeps its terminal in raw mode and forwards window-size changes and
 * signals. The exit status is passed back to the client.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#ifdef __ANDROID__
#include <android/log.h>
#endif

#include "password.h"

#define VERSION_NAME "headless_su 1.4 (password protected)"
#define VERSION_CODE 5
#define SOCKET_NAME "headless_su"
#ifndef DEFAULT_SHELL /* overridable for host testing */
#define DEFAULT_SHELL "/system/bin/sh"
#endif
#define DEFAULT_PATH "/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:" \
                     "/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin"
#define MAGIC 0x53554431u /* "SUD1" */
#ifndef AUTH_TIMEOUT /* overridable for host testing */
#define AUTH_TIMEOUT 60   /* seconds for the request and for each password answer */
#endif
#ifndef MAX_SESSIONS
#define MAX_SESSIONS 128  /* concurrent sessions, running root shells included */
#endif
#ifndef PACKAGES_LIST /* overridable for host testing */
#define PACKAGES_LIST "/data/system/packages.list"
#endif
#ifndef TICKET_TIMEOUT /* overridable for host testing; 0 disables unlocks */
#define TICKET_TIMEOUT 900 /* s a terminal session stays unlocked after its last su */
#endif
#define TICKET_SLOTS 64
#define TICKET_LOCK HEADLESS_SU_PW_DIR "/tickets.lock"

enum { MSG_READY = 1, MSG_EXIT = 2, MSG_WINCH = 3, MSG_SIGNAL = 4, MSG_AUTH = 5, MSG_DENY = 6 };
enum { F_LOGIN = 1, F_TTY0 = 2, F_TTY1 = 4, F_TTY2 = 8, F_FORGET = 16, F_NORUN = 32 };
#define TARGET_MOUNT_MASTER (-1)

struct msg {
    uint32_t type;
    int32_t value;
};

struct req {
    uint32_t magic;
    int32_t uid;
    int32_t target_pid; /* 0: caller, TARGET_MOUNT_MASTER: global, else pid */
    uint32_t flags;
    uint16_t rows, cols;
    uint32_t nargv, nenv;
};

/* ---------------------------------------------------------------- utils */

static void logi(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
#ifdef __ANDROID__
    __android_log_vprint(ANDROID_LOG_INFO, "su", fmt, ap);
#else
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
#endif
    va_end(ap);
}

static int xwrite(int fd, const void *buf, size_t len) {
    const char *p = buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int xread(int fd, void *buf, size_t len) {
    char *p = buf;
    while (len) {
        ssize_t n = read(fd, p, len);
        if (n == 0) return -1;
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int send_str(int fd, const char *s) {
    uint32_t l = (uint32_t)strlen(s);
    return (xwrite(fd, &l, sizeof l) || xwrite(fd, s, l)) ? -1 : 0;
}

static char *recv_str(int fd) {
    uint32_t l;
    if (xread(fd, &l, sizeof l) || l > (1u << 20)) return NULL;
    char *s = malloc(l + 1);
    if (!s) return NULL;
    if (xread(fd, s, l)) {
        free(s);
        return NULL;
    }
    s[l] = '\0';
    return s;
}

static int send_msg(int fd, uint32_t type, int32_t value) {
    struct msg m = {type, value};
    return xwrite(fd, &m, sizeof m);
}

static int send_fds(int sock, const int *fds, int n) {
    char dummy = 'F';
    struct iovec iov = {&dummy, 1};
    union {
        char buf[CMSG_SPACE(sizeof(int) * 3)];
        struct cmsghdr align;
    } u;
    memset(&u, 0, sizeof u);
    struct msghdr mh = {0};
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = u.buf;
    mh.msg_controllen = CMSG_SPACE(sizeof(int) * n);
    struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int) * n);
    memcpy(CMSG_DATA(c), fds, sizeof(int) * n);
    return sendmsg(sock, &mh, 0) == 1 ? 0 : -1;
}

static int recv_fds(int sock, int *fds, int n) {
    char dummy;
    struct iovec iov = {&dummy, 1};
    union {
        char buf[CMSG_SPACE(sizeof(int) * 3)];
        struct cmsghdr align;
    } u;
    struct msghdr mh = {0};
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = u.buf;
    mh.msg_controllen = sizeof u.buf;
    if (recvmsg(sock, &mh, MSG_CMSG_CLOEXEC) != 1) return -1;
    struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
    if (!c || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS ||
        c->cmsg_len != CMSG_LEN(sizeof(int) * n))
        return -1;
    memcpy(fds, CMSG_DATA(c), sizeof(int) * n);
    return 0;
}

static socklen_t make_addr(struct sockaddr_un *a) {
    const char *name = getenv("HEADLESS_SU_SOCKET");
    if (!name || !*name) name = SOCKET_NAME;
    memset(a, 0, sizeof *a);
    a->sun_family = AF_UNIX;
    size_t l = strlen(name);
    if (l > sizeof(a->sun_path) - 2) l = sizeof(a->sun_path) - 2;
    memcpy(a->sun_path + 1, name, l); /* leading NUL: abstract namespace */
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + l);
}

static int resolve_user(const char *name, uid_t *uid, gid_t *gid) {
    char *end;
    long v = strtol(name, &end, 10);
    if (*name && !*end && v >= 0 && v < INT_MAX) {
        struct passwd *pw = getpwuid((uid_t)v);
        *uid = (uid_t)v;
        *gid = pw ? pw->pw_gid : (gid_t)v;
        return 0;
    }
    struct passwd *pw = getpwnam(name);
    if (!pw) return -1;
    *uid = pw->pw_uid;
    *gid = pw->pw_gid;
    return 0;
}

/* Switch to uid/gid with the supplementary groups Android gives that user's
 * processes. An app uid gets what zygote gives the app: the gids its
 * permissions map to in packages.list (e.g. inet, without which DNS through
 * netd's dnsproxyd socket fails), everybody, and its cache and shared gids.
 * Any other non-root user gets none. */
static int switch_user(uid_t uid, gid_t gid) {
    gid_t groups[64];
    int n = 0;
    unsigned user = uid / 100000, app = uid % 100000;
    if (app >= 10000 && app <= 19999) { /* AID_APP_START..AID_APP_END */
        FILE *f = fopen(PACKAGES_LIST, "re");
        char line[2048];
        while (f && fgets(line, sizeof line, f)) {
            /* name uid debuggable datadir seinfo gids ... */
            char *save, *field = strtok_r(line, " \n", &save);
            int i = 0;
            unsigned long u = 0;
            while (field) {
                if (i == 1) u = strtoul(field, NULL, 10);
                if (i == 5 && u == app && strcmp(field, "none")) {
                    /* Packages sharing a uid each have a line: skip repeats. */
                    char *s2, *g = strtok_r(field, ",", &s2);
                    for (; g && n < 60; g = strtok_r(NULL, ",", &s2)) {
                        gid_t v = (gid_t)strtoul(g, NULL, 10);
                        int seen = 0;
                        for (int k = 0; k < n; k++) seen |= groups[k] == v;
                        if (!seen) groups[n++] = v;
                    }
                }
                field = strtok_r(NULL, " \n", &save);
                i++;
            }
        }
        if (f) fclose(f);
        groups[n++] = 9997;                                    /* AID_EVERYBODY */
        groups[n++] = user * 100000 + 20000 + (app - 10000);   /* cache gid */
        groups[n++] = 50000 + (app - 10000);                   /* shared gid */
    }
    if (setgroups((size_t)n, n ? groups : NULL) < 0 || setresgid(gid, gid, gid) < 0 ||
        setresuid(uid, uid, uid) < 0)
        return -1;
    return 0;
}

/* -------------------------------------------------------------- unlocks */

/* A caller's terminal session: what an unlock (ticket) is bound to. */
struct scope {
    uid_t uid;
    int32_t tty;                  /* controlling terminal (tty_nr of /proc/PID/stat) */
    pid_t sid;                    /* session id */
    unsigned long long sid_start; /* the session leader's start time */
};

struct ticket {
    struct scope s;
    int64_t used;         /* CLOCK_BOOTTIME s of the unlock or last use; 0 = free slot */
    uint64_t pw_stamp[2]; /* identity of the password file at unlock time */
};

/* TICKET_SLOTS tickets in a MAP_SHARED mapping made by the daemon, so every
 * session process it forks sees and updates the same table. */
static struct ticket *g_tickets;

/* session, tty_nr and starttime (fields 6, 7, 22) of /proc/PID/stat */
static int proc_stat(pid_t pid, pid_t *sid, int32_t *tty, unsigned long long *start) {
    char path[32], buf[1024];
    snprintf(path, sizeof path, "/proc/%d/stat", (int)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    char *p = strrchr(buf, ')'); /* the command name may contain anything */
    if (!p) return -1;
    char *save, *f = strtok_r(p + 1, " ", &save);
    for (int i = 3; f; f = strtok_r(NULL, " ", &save), i++) {
        if (i == 6) *sid = (pid_t)strtol(f, NULL, 10);
        else if (i == 7) *tty = (int32_t)strtol(f, NULL, 10);
        else if (i == 22) {
            *start = strtoull(f, NULL, 10);
            return 0;
        }
    }
    return -1;
}

/* The caller's session, if it has a controlling terminal: 0, else -1. */
static int caller_scope(const struct ucred *cr, struct scope *s) {
    memset(s, 0, sizeof *s);
    unsigned long long start;
    if (proc_stat(cr->pid, &s->sid, &s->tty, &start) < 0 || s->tty == 0 || s->sid <= 0)
        return -1;
    pid_t lsid;
    int32_t ltty;
    if (proc_stat(s->sid, &lsid, &ltty, &s->sid_start) < 0 || lsid != s->sid)
        return -1; /* the session leader is gone (or its pid was reused) */
    s->uid = cr->uid;
    return 0;
}

static int scope_eq(const struct scope *a, const struct scope *b) {
    return a->uid == b->uid && a->tty == b->tty && a->sid == b->sid &&
           a->sid_start == b->sid_start;
}

static void pw_stamp(uint64_t st[2]) { /* set_root_pwd renames a new file in */
    struct stat sb;
    st[0] = st[1] = 0;
    if (stat(HEADLESS_SU_PW_PATH, &sb) == 0) {
        st[0] = (uint64_t)sb.st_ino;
        st[1] = (uint64_t)sb.st_mtim.tv_sec * 1000000000u + (uint64_t)sb.st_mtim.tv_nsec;
    }
}

static int64_t boottime(void) { /* keeps counting while the phone sleeps */
    struct timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);
    return (int64_t)ts.tv_sec;
}

/* Exclusive access to the table: a lock file opened per process (flock locks
 * belong to the open file, so an inherited descriptor would not exclude), with
 * SIGALRM held off so a timing-out session cannot die halfway through an
 * update. Returns the lock fd, or -1: then tickets are not used at all. */
static int ticket_lock(sigset_t *old) {
    if (!g_tickets || TICKET_TIMEOUT <= 0) return -1;
    mkdir(HEADLESS_SU_PW_DIR, 0700);
    int fd = open(TICKET_LOCK, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd >= 0 && flock(fd, LOCK_EX) < 0) {
        close(fd);
        fd = -1;
    }
    if (fd >= 0) {
        sigset_t alrm;
        sigemptyset(&alrm);
        sigaddset(&alrm, SIGALRM);
        sigprocmask(SIG_BLOCK, &alrm, old);
    }
    return fd;
}

static void ticket_unlock(int fd, const sigset_t *old) {
    close(fd);
    sigprocmask(SIG_SETMASK, old, NULL);
}

/* 1 if the session is unlocked (and renew it), 0 if the password is needed. */
static int ticket_use(const struct scope *s) {
    sigset_t old;
    int lk = ticket_lock(&old);
    if (lk < 0) return 0;
    uint64_t pw[2];
    pw_stamp(pw);
    int64_t now = boottime();
    int ok = 0;
    for (int i = 0; i < TICKET_SLOTS; i++) {
        struct ticket *t = &g_tickets[i];
        if (!t->used || !scope_eq(&t->s, s)) continue;
        if (now >= t->used && now - t->used < TICKET_TIMEOUT && !memcmp(t->pw_stamp, pw, sizeof pw)) {
            t->used = now;
            ok = 1;
        } else {
            t->used = 0; /* expired, or the password changed since */
        }
    }
    ticket_unlock(lk, &old);
    return ok;
}

/* After a correct password: unlock the session (reusing its slot, a free or
 * expired one, or else the least recently used). */
static void ticket_store(const struct scope *s) {
    sigset_t old;
    int lk = ticket_lock(&old);
    if (lk < 0) return;
    int64_t now = boottime();
    struct ticket *slot = NULL;
    for (int i = 0; i < TICKET_SLOTS && !slot; i++) {
        struct ticket *t = &g_tickets[i];
        if (t->used && now - t->used >= TICKET_TIMEOUT) t->used = 0; /* expired */
        if (t->used && scope_eq(&t->s, s)) slot = t;
    }
    if (!slot) /* a free slot (used == 0), else the least recently used */
        for (int i = 0; i < TICKET_SLOTS; i++)
            if (!slot || g_tickets[i].used < slot->used) slot = &g_tickets[i];
    __atomic_store_n(&slot->used, 0, __ATOMIC_SEQ_CST); /* free until complete */
    slot->s = *s;
    pw_stamp(slot->pw_stamp);
    __atomic_store_n(&slot->used, now > 0 ? now : 1, __ATOMIC_SEQ_CST);
    ticket_unlock(lk, &old);
}

static int ticket_forget(const struct scope *s) {
    sigset_t old;
    int lk = ticket_lock(&old), n = 0;
    if (lk < 0) return 0;
    for (int i = 0; i < TICKET_SLOTS; i++)
        if (g_tickets[i].used && scope_eq(&g_tickets[i].s, s)) {
            g_tickets[i].used = 0;
            n++;
        }
    ticket_unlock(lk, &old);
    return n;
}

/* --------------------------------------------------------------- daemon */

static void exec_child(const struct req *r, pid_t ns_pid, const int *fds, int slave,
                       const char *cwd, const char *path, char **argv, char **envp) {
    for (int s = 1; s < NSIG; s++) signal(s, SIG_DFL);
    sigset_t m;
    sigemptyset(&m);
    sigprocmask(SIG_SETMASK, &m, NULL);

    setsid();
    if (slave >= 0) ioctl(slave, TIOCSCTTY, 0);
    for (int i = 0; i < 3; i++) {
        int src = (r->flags & (F_TTY0 << i)) ? slave : fds[i];
        if (dup2(src, i) < 0) _exit(127);
    }

    if (ns_pid > 0) {
        char p[64];
        snprintf(p, sizeof p, "/proc/%d/ns/mnt", (int)ns_pid);
        int nfd = open(p, O_RDONLY | O_CLOEXEC);
        if (nfd < 0 || setns(nfd, CLONE_NEWNS) < 0)
            dprintf(2, "su: warning: cannot enter mount namespace of pid %d: %s\n",
                    (int)ns_pid, strerror(errno));
        if (nfd >= 0) close(nfd);
    }
    if (chdir(cwd) < 0 && chdir("/") < 0) _exit(127);

    if (r->uid != 0) {
        uid_t uid;
        gid_t gid;
        char ubuf[16];
        snprintf(ubuf, sizeof ubuf, "%d", r->uid);
        if (resolve_user(ubuf, &uid, &gid) < 0) {
            uid = (uid_t)r->uid;
            gid = (gid_t)r->uid;
        }
        if (switch_user(uid, gid) < 0) {
            dprintf(2, "su: cannot switch to uid %d: %s\n", r->uid, strerror(errno));
            _exit(1);
        }
    }

    execve(path, argv, envp);
    dprintf(2, "su: %s: %s\n", path, strerror(errno));
    _exit(127);
}

static int session(int c) {
    alarm(AUTH_TIMEOUT); /* SIGALRM ends a session that stalls before authenticating */
    struct ucred cr;
    socklen_t crl = sizeof cr;
    if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cr, &crl) < 0) return 1;

    struct req r;
    if (xread(c, &r, sizeof r) || r.magic != MAGIC || r.nargv < 1 || r.nargv > 4096 ||
        r.nenv > 16384)
        return 1;
    char *cwd = recv_str(c), *path = recv_str(c);
    if (!cwd || !path) return 1;
    char **argv = calloc(r.nargv + 1, sizeof *argv);
    char **envp = calloc(r.nenv + 1, sizeof *envp);
    if (!argv || !envp) return 1;
    for (uint32_t i = 0; i < r.nargv; i++)
        if (!(argv[i] = recv_str(c))) return 1;
    for (uint32_t i = 0; i < r.nenv; i++)
        if (!(envp[i] = recv_str(c))) return 1;
    int fds[3];
    if (recv_fds(c, fds, 3)) return 1;

    struct scope sc;
    int has_scope = caller_scope(&cr, &sc) == 0; /* has a terminal: unlocks apply */
    if (r.flags & F_FORGET) { /* su -k */
        if (has_scope) ticket_forget(&sc);
        if (r.flags & F_NORUN) {
            alarm(0);
            send_msg(c, MSG_EXIT, 0);
            return 0;
        }
    }

    /* Password gate: the caller must know the root password (the default is
     * "root" until 'set_root_pwd' has written a hash; see password.c), unless
     * its terminal session is still unlocked from an earlier su. */
    int cached = has_scope && ticket_use(&sc);
    for (int attempts = 3; !cached;) {
        alarm(AUTH_TIMEOUT);
        if (send_msg(c, MSG_AUTH, attempts) < 0) return 1;
        char *pw = recv_str(c);
        if (!pw) return 1;
        /* One check at a time device-wide, failure delay included, so that
         * parallel connections cannot multiply the guessing rate. */
        int lk = password_lock();
        if (lk < 0) logi("cannot lock %s: %s", HEADLESS_SU_PW_LOCK, strerror(errno));
        int ok = password_verify(pw);
        password_wipe(pw, strlen(pw));
        free(pw);
        if (ok == 1) {
            if (lk >= 0) close(lk);
            break;
        }
        attempts--;
        if (attempts <= 0)
            logi("uid %d (pid %d): authentication failure", (int)cr.uid, (int)cr.pid);
        send_msg(c, MSG_DENY, attempts);
        usleep(1000000); /* slow down brute force over the local socket */
        if (lk >= 0) close(lk);
        if (attempts <= 0) return 1;
    }
    if (!cached && has_scope) ticket_store(&sc);
    alarm(0);

    logi("uid %d (pid %d) -> uid %d%s: %s%s%s", (int)cr.uid, (int)cr.pid, r.uid,
         cached ? " (unlocked session)" : "", path,
         r.nargv > 2 && !strcmp(argv[1], "-c") ? " -c " : "",
         r.nargv > 2 && !strcmp(argv[1], "-c") ? argv[2] : "");

    int master = -1, slave = -1;
    if (r.flags & (F_TTY0 | F_TTY1 | F_TTY2)) {
        master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
        if (master < 0 || grantpt(master) < 0 || unlockpt(master) < 0) return 1;
        char *pts = ptsname(master);
        if (!pts || (slave = open(pts, O_RDWR | O_NOCTTY | O_CLOEXEC)) < 0) return 1;
        int tfd = (r.flags & F_TTY0) ? fds[0] : (r.flags & F_TTY1) ? fds[1] : fds[2];
        struct termios t;
        if (tcgetattr(tfd, &t) == 0) tcsetattr(slave, TCSANOW, &t);
        if (r.rows && r.cols) {
            struct winsize ws = {.ws_row = r.rows, .ws_col = r.cols};
            ioctl(master, TIOCSWINSZ, &ws);
        }
    }

    pid_t ns_pid = r.target_pid == TARGET_MOUNT_MASTER ? 0
                   : r.target_pid > 0                  ? r.target_pid
                                                       : cr.pid;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) exec_child(&r, ns_pid, fds, slave, cwd, path, argv, envp);
    if (slave >= 0) close(slave);
    send_msg(c, MSG_READY, child);

    /* Relay: caller terminal <-> pty master; control messages on the socket. */
    int in_fd = (master >= 0 && (r.flags & F_TTY0)) ? fds[0] : -1;
    int out_fd = master < 0 ? -1
                 : (r.flags & F_TTY1) ? fds[1]
                 : (r.flags & F_TTY2) ? fds[2]
                                      : fds[0]; /* echo back to the input terminal */
    int child_done = 0, status = 0;
    char buf[16384];
    for (;;) {
        struct pollfd pf[3];
        int n = 0, ci = -1, mi = -1, ii = -1;
        if (c >= 0) { pf[n] = (struct pollfd){c, POLLIN, 0}; ci = n++; }
        if (master >= 0) { pf[n] = (struct pollfd){master, POLLIN, 0}; mi = n++; }
        if (in_fd >= 0 && !child_done) { pf[n] = (struct pollfd){in_fd, POLLIN, 0}; ii = n++; }
        int pr = poll(pf, (nfds_t)n, child_done ? 50 : 250);
        if (!child_done && waitpid(child, &status, WNOHANG) == child) child_done = 1;
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ci >= 0 && pf[ci].revents) {
            struct msg m;
            if ((pf[ci].revents & POLLIN) && xread(c, &m, sizeof m) == 0) {
                if (m.type == MSG_WINCH && master >= 0) {
                    struct winsize ws = {.ws_row = (unsigned short)((uint32_t)m.value >> 16),
                                         .ws_col = (unsigned short)(m.value & 0xffff)};
                    ioctl(master, TIOCSWINSZ, &ws);
                } else if (m.type == MSG_SIGNAL && m.value > 0 && m.value < NSIG && !child_done) {
                    kill(-child, m.value);
                }
            } else { /* client went away: hang up the session */
                if (!child_done) kill(-child, SIGHUP);
                close(c);
                c = -1;
            }
        }
        if (mi >= 0 && pf[mi].revents) {
            ssize_t k = read(master, buf, sizeof buf);
            if (k > 0) {
                if (out_fd >= 0 && xwrite(out_fd, buf, (size_t)k) < 0) out_fd = -1;
            } else if (!(k < 0 && errno == EINTR)) { /* EIO: no slave left */
                close(master);
                master = -1;
            }
        }
        if (ii >= 0 && pf[ii].revents) {
            ssize_t k = read(in_fd, buf, sizeof buf);
            if (k > 0) {
                if (master >= 0) xwrite(master, buf, (size_t)k);
            } else if (!(k < 0 && (errno == EINTR || errno == EAGAIN))) {
                in_fd = -1;
            }
        }
        if (child_done && (master < 0 || pr == 0)) break; /* output drained */
    }
    if (!child_done) waitpid(child, &status, 0);
    int code = WIFEXITED(status) ? WEXITSTATUS(status)
               : WIFSIGNALED(status) ? 128 + WTERMSIG(status)
                                     : 1;
    if (c >= 0) send_msg(c, MSG_EXIT, code);
    return 0;
}

static volatile sig_atomic_t g_sessions; /* live session processes */

static void on_sigchld(int sig) {
    (void)sig;
    int saved = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0) g_sessions--;
    errno = saved;
}

static int daemon_main(void) {
    if (getuid() != 0) {
        fprintf(stderr, "su: --daemon must run as root\n");
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sigchld; /* reaps session handlers and counts them */
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
    sigset_t chld, prev;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    time_t last_full_log = 0;
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un a;
    socklen_t alen = make_addr(&a);
    if (s < 0 || bind(s, (struct sockaddr *)&a, alen) < 0 || listen(s, 64) < 0) {
        logi("daemon: cannot listen on @%s: %s", a.sun_path + 1, strerror(errno));
        return 1;
    }
    g_tickets = mmap(NULL, TICKET_SLOTS * sizeof *g_tickets, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (g_tickets == MAP_FAILED) { /* then every su asks for the password */
        g_tickets = NULL;
        logi("daemon: no memory for unlocked sessions: %s", strerror(errno));
    }
    logi("daemon: listening on @%s (%s)", a.sun_path + 1, VERSION_NAME);
    for (;;) {
        int c = accept4(s, NULL, NULL, SOCK_CLOEXEC);
        if (c < 0) {
            if (errno != EINTR) usleep(100000);
            continue;
        }
        sigprocmask(SIG_BLOCK, &chld, &prev); /* g_sessions is also changed by on_sigchld */
        if (g_sessions >= MAX_SESSIONS) {
            sigprocmask(SIG_SETMASK, &prev, NULL);
            if (time(NULL) != last_full_log) { /* at most one log line per second */
                last_full_log = time(NULL);
                logi("daemon: %d sessions active, refusing connections", MAX_SESSIONS);
            }
            close(c);
            continue;
        }
        pid_t p = fork();
        if (p == 0) {
            close(s);
            signal(SIGCHLD, SIG_DFL);
            sigprocmask(SIG_SETMASK, &prev, NULL);
            _exit(session(c));
        }
        if (p > 0) g_sessions++;
        sigprocmask(SIG_SETMASK, &prev, NULL);
        close(c);
    }
}

/* --------------------------------------------------------------- client */

static int g_sock = -1, g_raw_fd = -1, g_tty_fd = -1;
static struct termios g_saved;

static void restore_tty(void) {
    if (g_raw_fd >= 0) {
        tcsetattr(g_raw_fd, TCSADRAIN, &g_saved);
        g_raw_fd = -1;
    }
}

static void send_winch(void) {
    struct winsize ws;
    if (g_tty_fd >= 0 && ioctl(g_tty_fd, TIOCGWINSZ, &ws) == 0)
        send_msg(g_sock, MSG_WINCH, (int32_t)(((uint32_t)ws.ws_row << 16) | ws.ws_col));
}

static void on_signal(int sig) {
    int saved = errno;
    if (sig == SIGWINCH) send_winch();
    else send_msg(g_sock, MSG_SIGNAL, sig);
    errno = saved;
}

static void usage(FILE *f) {
    fprintf(f,
            "%s\n"
            "Usage: su [options] [-] [user [args...]]\n"
            "  -c, --command CMD     run CMD (rest of the arguments) with sh -c\n"
            "  -s, --shell SHELL     use SHELL instead of " DEFAULT_SHELL "\n"
            "  -l, --login, -        login-style environment, start in /\n"
            "  -p, -m, --preserve-environment  (default) keep the environment\n"
            "  -M, -mm, --mount-master         use the global mount namespace\n"
            "  -t, --target PID      use the mount namespace of PID\n"
            "  -k, --reset-timestamp forget this terminal session's unlock; alone,\n"
            "                        only that (otherwise the password is asked again)\n"
            "  -v, --version / -V    print version name / code\n"
            "  su --daemon           run the root daemon (started by init)\n",
            VERSION_NAME);
}

static char **build_env(int login, const char *shell, const char *user) {
    extern char **environ;
    size_t n = 0;
    while (environ[n]) n++;
    char **env = calloc(n + 8, sizeof *env);
    size_t k = 0;
    if (!login) {
        for (size_t i = 0; i < n; i++) env[k++] = environ[i];
        return env;
    }
    static const char *drop[] = {"PATH=", "HOME=", "SHELL=", "USER=", "LOGNAME=",
                                 "LD_PRELOAD=", "LD_LIBRARY_PATH=", "PREFIX=", NULL};
    for (size_t i = 0; i < n; i++) {
        int skip = 0;
        for (const char **d = drop; *d; d++)
            if (!strncmp(environ[i], *d, strlen(*d))) skip = 1;
        if (!skip) env[k++] = environ[i];
    }
    char *s;
    env[k++] = "PATH=" DEFAULT_PATH;
    env[k++] = "HOME=/";
    if (asprintf(&s, "SHELL=%s", shell) > 0) env[k++] = s;
    if (asprintf(&s, "USER=%s", user) > 0) env[k++] = s;
    if (asprintf(&s, "LOGNAME=%s", user) > 0) env[k++] = s;
    return env;
}

static int client_main(int argc, char **argv) {
    const char *shell = DEFAULT_SHELL, *user = "root";
    char *command = NULL;
    int login = 0, forget = 0;
    int32_t target = 0;

    for (int i = 1; i < argc; i++) /* Magisk compatibility: "-mm" == "--mount-master" */
        if (!strcmp(argv[i], "-mm")) argv[i] = "-M";

    static const struct option opts[] = {
        {"command", required_argument, NULL, 'c'},
        {"shell", required_argument, NULL, 's'},
        {"login", no_argument, NULL, 'l'},
        {"preserve-environment", no_argument, NULL, 'p'},
        {"mount-master", no_argument, NULL, 'M'},
        {"target", required_argument, NULL, 't'},
        {"context", required_argument, NULL, 'Z'},
        {"reset-timestamp", no_argument, NULL, 'k'},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'v'},
        {NULL, 0, NULL, 0}};
    int o;
    while ((o = getopt_long(argc, argv, "c:s:lpmMt:Z:khvV", opts, NULL)) != -1) {
        switch (o) {
        case 'c': { /* like Magisk/SuperSU: the command is the rest of argv */
            size_t len = 1;
            for (int i = optind - 1; i < argc; i++) len += strlen(argv[i]) + 1;
            command = calloc(len, 1);
            for (int i = optind - 1; i < argc; i++) {
                if (i > optind - 1) strcat(command, " ");
                strcat(command, argv[i]);
            }
            optind = argc;
            break;
        }
        case 's': shell = optarg; break;
        case 'l': login = 1; break;
        case 'p': case 'm': case 'Z': break;
        case 'M': target = TARGET_MOUNT_MASTER; break;
        case 't': target = atoi(optarg); break;
        case 'k': forget = 1; break;
        case 'h': usage(stdout); return 0;
        case 'v': printf("%s\n", VERSION_NAME); return 0;
        case 'V': printf("%d\n", VERSION_CODE); return 0;
        default: usage(stderr); return 2;
        }
    }
    char **extra = calloc((size_t)argc + 1, sizeof *extra);
    int nextra = 0, have_user = 0;
    for (int i = optind; i < argc; i++) {
        if (!strcmp(argv[i], "-")) login = 1;
        else if (!have_user) { user = argv[i]; have_user = 1; }
        else extra[nextra++] = argv[i];
    }

    uid_t uid;
    gid_t gid;
    if (resolve_user(user, &uid, &gid) < 0) {
        fprintf(stderr, "su: unknown user %s\n", user);
        return 1;
    }

    /* Child argv: [-]sh [-c CMD] [args...] */
    const char *base = strrchr(shell, '/');
    base = base ? base + 1 : shell;
    char *argv0 = (char *)shell;
    if (login && asprintf(&argv0, "-%s", base) < 0) return 1;
    char **cargv = calloc((size_t)nextra + 4, sizeof *cargv);
    int ca = 0;
    cargv[ca++] = argv0;
    if (command) {
        cargv[ca++] = "-c";
        cargv[ca++] = command;
    }
    for (int i = 0; i < nextra; i++) cargv[ca++] = extra[i];
    char **cenv = build_env(login, shell, user);
    char cwd_buf[PATH_MAX];
    const char *cwd = login ? "/" : (getcwd(cwd_buf, sizeof cwd_buf) ? cwd_buf : "/");

    /* "su -k" alone only forgets the unlock, like "sudo -k". */
    int norun = forget && !command && !have_user && !nextra && !login;

    /* Already root: no daemon needed. */
    if (geteuid() == 0) {
        if (norun) return 0;
        if (uid != 0 && switch_user(uid, gid) < 0) {
            perror("su");
            return 1;
        }
        if (login && chdir("/") < 0) perror("su: chdir");
        execve(shell, cargv, cenv);
        fprintf(stderr, "su: %s: %s\n", shell, strerror(errno));
        return 127;
    }

    signal(SIGPIPE, SIG_IGN);
    g_sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un a;
    socklen_t alen = make_addr(&a);
    if (g_sock < 0 || connect(g_sock, (struct sockaddr *)&a, alen) < 0) {
        fprintf(stderr, "su: cannot reach the su daemon (@%s): %s - is service 'sud' running?\n",
                a.sun_path + 1, strerror(errno));
        return 1;
    }
    /* Only talk to a root daemon: while sud is not running, any process could
     * bind the abstract name and collect the password. */
    struct ucred dc;
    socklen_t dcl = sizeof dc;
    if (getsockopt(g_sock, SOL_SOCKET, SO_PEERCRED, &dc, &dcl) < 0 || dc.uid != 0) {
        fprintf(stderr, "su: @%s is not served by root, refusing\n", a.sun_path + 1);
        return 1;
    }

    for (int i = 0; i < 3; i++) /* make sure 0..2 exist so they can be passed */
        if (fcntl(i, F_GETFD) < 0) open("/dev/null", O_RDWR);

    struct req r = {0};
    r.magic = MAGIC;
    r.uid = (int32_t)uid;
    r.target_pid = target;
    r.flags = (login ? F_LOGIN : 0) | (forget ? F_FORGET : 0) | (norun ? F_NORUN : 0);
    for (int i = 0; i < 3; i++)
        if (isatty(i)) {
            r.flags |= (uint32_t)(F_TTY0 << i);
            if (g_tty_fd < 0) g_tty_fd = i;
        }
    struct winsize ws;
    if (g_tty_fd >= 0 && ioctl(g_tty_fd, TIOCGWINSZ, &ws) == 0) {
        r.rows = ws.ws_row;
        r.cols = ws.ws_col;
    }
    r.nargv = (uint32_t)ca;
    while (cenv[r.nenv]) r.nenv++;

    int fds[3] = {0, 1, 2};
    int bad = xwrite(g_sock, &r, sizeof r) || send_str(g_sock, cwd) || send_str(g_sock, shell);
    for (int i = 0; !bad && i < ca; i++) bad = send_str(g_sock, cargv[i]);
    for (uint32_t i = 0; !bad && i < r.nenv; i++) bad = send_str(g_sock, cenv[i]);
    if (!bad) bad = send_fds(g_sock, fds, 3);
    if (bad) {
        fprintf(stderr, "su: failed to send the request to the su daemon\n");
        return 1;
    }

    /* Authenticate: the daemon asks (MSG_AUTH), we prompt and answer. */
    struct msg m;
    for (;;) {
        if (xread(g_sock, &m, sizeof m) < 0) {
            fprintf(stderr, "su: lost connection to the su daemon\n");
            return 1;
        }
        if (m.type == MSG_READY) break;
        if (m.type == MSG_EXIT) return m.value; /* su -k: nothing to run */
        if (m.type == MSG_AUTH) {
            char pw[HEADLESS_SU_PW_MAX];
            if (read_password("Password: ", pw, sizeof pw) < 0) {
                fprintf(stderr, "su: no password given\n"); /* EOF: no tty, empty stdin */
                return 1;
            }
            int wr = send_str(g_sock, pw);
            password_wipe(pw, sizeof pw);
            if (wr < 0) {
                fprintf(stderr, "su: lost connection to the su daemon\n");
                return 1;
            }
            continue;
        }
        if (m.type == MSG_DENY) {
            if (m.value > 0) { /* the daemon will ask again with MSG_AUTH */
                fprintf(stderr, "su: incorrect password\n");
                continue;
            }
            fprintf(stderr, "su: authentication failure\n");
            return 1;
        }
        fprintf(stderr, "su: unexpected response from the su daemon\n");
        return 1;
    }

    /* Terminal input is relayed by the daemon into the pty: put ours in raw mode. */
    if ((r.flags & F_TTY0) && tcgetattr(0, &g_saved) == 0) {
        struct termios raw = g_saved;
        cfmakeraw(&raw);
        if (tcsetattr(0, TCSADRAIN, &raw) == 0) {
            g_raw_fd = 0;
            atexit(restore_tty);
        }
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sa.sa_flags = SA_RESTART;
    int sigs[] = {SIGWINCH, SIGINT, SIGQUIT, SIGTERM, SIGHUP, SIGUSR1, SIGUSR2};
    for (size_t i = 0; i < sizeof sigs / sizeof *sigs; i++) sigaction(sigs[i], &sa, NULL);

    for (;;) {
        ssize_t k = read(g_sock, &m, sizeof m);
        if (k < 0 && errno == EINTR) continue;
        if (k == (ssize_t)sizeof m && m.type == MSG_EXIT) {
            restore_tty();
            return m.value;
        }
        if (k <= 0) {
            restore_tty();
            fprintf(stderr, "su: lost connection to the su daemon\n");
            return 1;
        }
    }
}

int main(int argc, char **argv) {
    if (argc >= 2 && !strcmp(argv[1], "--daemon")) return daemon_main();
    return client_main(argc, argv);
}
