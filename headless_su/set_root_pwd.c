/*
 * set_root_pwd - set (or clear) the headless_su root password.
 *
 * Must run as root, i.e. through 'su' with the current password (or via
 * 'adb root'). Writes a salted SHA-256 hash to /data/misc/headless_su/passwd
 * (mode 0600); 'su' then requires that password instead of the default "root".
 *
 *   set_root_pwd              prompt for a new password (twice, no echo)
 *   echo NEWPASS | set_root_pwd   read one line from stdin when it is not a terminal
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
            "              (or read one line from stdin if it is not a terminal)\n"
            "  --clear     remove the password; the default \"root\" works again\n");
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

    char a[HEADLESS_SU_PW_MAX] = "", b[HEADLESS_SU_PW_MAX] = "";
    /* Piped stdin wins over the terminal, so 'echo pw | su -c set_root_pwd'
     * works even though the su session has a controlling tty. */
    int interactive = isatty(STDIN_FILENO);
    int rc = interactive ? read_password("New password: ", a, sizeof a)
                         : password_read_line(STDIN_FILENO, a, sizeof a);
    if (rc < 0) {
        fprintf(stderr, "set_root_pwd: cannot read a password\n");
        return 1;
    }
    if (!a[0]) {
        fprintf(stderr, "set_root_pwd: empty password, refusing\n");
        return 1;
    }
    if (interactive) {
        if (read_password("Retype new password: ", b, sizeof b) < 0) {
            fprintf(stderr, "set_root_pwd: cannot read a password\n");
            password_wipe(a, sizeof a);
            return 1;
        }
        if (strcmp(a, b) != 0) {
            fprintf(stderr, "set_root_pwd: passwords do not match\n");
            password_wipe(a, sizeof a);
            password_wipe(b, sizeof b);
            return 1;
        }
    }

    rc = password_set(a);
    password_wipe(a, sizeof a);
    password_wipe(b, sizeof b);
    if (rc < 0) {
        fprintf(stderr, "set_root_pwd: cannot store the password: %s\n", strerror(errno));
        return 1;
    }
    printf("headless_su: root password updated\n");
    return 0;
}
