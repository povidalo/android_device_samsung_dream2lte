/*
 * set_root_pwd - set (or clear) the headless_su root password.
 *
 * Must run as root, i.e. through 'su' with the current password (or via
 * 'adb root'). Writes a salted SHA-256 hash to /data/misc/headless_su/passwd
 * (mode 0600); 'su' then requires that password instead of the default "root".
 *
 *   set_root_pwd              prompt for a new password (twice, no echo)
 *   echo NEWPASS | set_root_pwd   read the password from stdin (no echo issue)
 *   set_root_pwd --clear      delete the hash; the default "root" applies again
 *
 * A password is never taken from argv, so it cannot leak through ps.
 */
#include "password.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void usage(FILE *f) {
    fprintf(f,
            "Usage: set_root_pwd [--clear]\n"
            "  (no args)   prompt for a new root password for headless_su\n"
            "  --clear     remove the password; the default \"root\" works again\n");
}

static void wipe(char *s) {
    volatile char *v = s;
    while (*v) *v++ = 0;
}

int main(int argc, char **argv) {
    if (geteuid() != 0) {
        fprintf(stderr, "set_root_pwd: must run as root (use 'su' or 'adb root')\n");
        return 1;
    }
    if (argc > 1) {
        if (!strcmp(argv[1], "--clear") || !strcmp(argv[1], "-d")) {
            if (password_clear() < 0) {
                fprintf(stderr, "set_root_pwd: cannot clear: %s\n", strerror(errno));
                return 1;
            }
            printf("headless_su: password cleared (default password \"root\" is active)\n");
            return 0;
        }
        if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
            usage(stdout);
            return 0;
        }
        usage(stderr);
        return 2;
    }

    char a[HEADLESS_SU_PW_MAX], b[HEADLESS_SU_PW_MAX];
    if (read_password("New password: ", a, sizeof a) < 0) {
        fprintf(stderr, "set_root_pwd: cannot read a password\n");
        return 1;
    }
    if (!a[0]) {
        fprintf(stderr, "set_root_pwd: empty password, refusing\n");
        return 1;
    }
    if (password_on_tty()) {
        if (read_password("Retype new password: ", b, sizeof b) < 0) {
            fprintf(stderr, "set_root_pwd: cannot read a password\n");
            wipe(a);
            return 1;
        }
        if (strcmp(a, b) != 0) {
            fprintf(stderr, "set_root_pwd: passwords do not match\n");
            wipe(a);
            wipe(b);
            return 1;
        }
    }

    int rc = password_set(a);
    wipe(a);
    wipe(b);
    if (rc < 0) {
        fprintf(stderr, "set_root_pwd: cannot store the password: %s\n", strerror(errno));
        return 1;
    }
    printf("headless_su: root password updated\n");
    return 0;
}
