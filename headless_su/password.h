/*
 * headless_su password store.
 *
 * The root password is a salted SHA-256 hash kept in a root-only file.
 * When the file is absent the password is the literal default "root"; as soon
 * as 'set_root_pwd' writes a hash, the default no longer works.
 *
 *   password_verify()   1 = accepted, 0 = rejected, -1 = store unreadable/corrupt
 *   password_set()      write a new salted hash (0 = ok)
 *   password_clear()    remove the hash, restoring the default (0 = ok)
 *   read_password()     prompt on the terminal with echo off (falls back to stdin)
 */
#ifndef HEADLESS_SU_PASSWORD_H
#define HEADLESS_SU_PASSWORD_H

#include <stddef.h>

#ifndef HEADLESS_SU_PW_DIR
#define HEADLESS_SU_PW_DIR "/data/misc/headless_su"
#endif
#define HEADLESS_SU_PW_PATH HEADLESS_SU_PW_DIR "/passwd"
#define HEADLESS_SU_PW_DEFAULT "root"
#define HEADLESS_SU_PW_MAX 256

int password_verify(const char *pw);
int password_set(const char *pw);
int password_clear(void);
int read_password(const char *prompt, char *buf, size_t size);
int password_on_tty(void);

void password_sha256(const void *data, size_t len, unsigned char out[32]);

#endif
