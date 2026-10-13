#!/system/bin/sh
# headless_boot - run the root boot scripts in /data/local/boot.d once per boot
# (started by init on sys.boot_completed=1, see sud.rc).
#
#   /data/local/boot.d/      root-only (0700, created on first boot). Every
#                            executable file runs, in name order, one at a time;
#                            'chmod -x' disables a script. A script must return:
#                            start long-running daemons in the background (and
#                            redirect their output). A script still running
#                            after SCRIPT_TIMEOUT seconds is killed.
#   /data/local/boot.d.log   output of this boot's run (previous boot: .old)
#
# Scripts run as root in the global mount namespace (like 'su -M'), so mounts
# they make propagate into the apps' namespaces. When Termux is installed they
# get its environment, as with tsu: Termux's bash, PREFIX, PATH, TMPDIR, LANG,
# LD_PRELOAD=termux-exec (so '#!/usr/bin/env ...' shebangs work) and
# HOME=~/.suroot (root's files stay out of Termux's home). Termux packages
# (docker, mount.cifs, rclone, ...) then work as root. Without Termux, scripts
# run with /system/bin/sh.
#
# This service never exits: init kills the processes of a stopped service,
# which would take the daemons started by the scripts with it. If it is killed
# anyway, init restarts it and the scripts run again, so keep them idempotent
# (e.g. check 'mountpoint -q' before mounting).

DIR=${HEADLESS_BOOT_DIR:-/data/local/boot.d}      # overridable for host testing
LOG=${HEADLESS_BOOT_LOG:-/data/local/boot.d.log}
TERMUX=${HEADLESS_BOOT_TERMUX:-/data/data/com.termux/files}
SCRIPT_TIMEOUT=${HEADLESS_BOOT_TIMEOUT:-300}

say() {
    echo "$(date '+%F %T') headless_boot: $*" >>"$LOG"
    [ -x /system/bin/log ] && /system/bin/log -t headless_boot "$*"
}

umask 077 # the directory, the log and ~/.suroot are root-only
mkdir -p "$DIR" && chmod 0700 "$DIR"
[ -f "$LOG" ] && mv -f "$LOG" "$LOG.old"
: >"$LOG"

P= PRELOAD=
if [ -x "$TERMUX/usr/bin/bash" ]; then
    P=$TERMUX/usr
    for l in libtermux-exec-ld-preload.so libtermux-exec.so; do
        if [ -f "$P/lib/$l" ]; then PRELOAD=$P/lib/$l; break; fi
    done
    ROOTHOME=$TERMUX/home/.suroot
    mkdir -p "$ROOTHOME"
    say "Termux environment: PREFIX=$P${PRELOAD:+ LD_PRELOAD=$PRELOAD}"
else
    say "Termux is not installed: scripts run with /system/bin/sh"
fi

# timeout and env stay outside the Termux environment: only the script's shell
# gets LD_PRELOAD, so no system binary tries to load termux-exec.
run_script() {
    if [ -n "$P" ]; then
        timeout -k 10 "$SCRIPT_TIMEOUT" env PREFIX="$P" HOME="$ROOTHOME" \
            TMPDIR="$P/tmp" PATH="$P/bin:$PATH" LANG=en_US.UTF-8 SHELL="$P/bin/bash" \
            ${PRELOAD:+LD_PRELOAD="$PRELOAD"} "$P/bin/bash" -c 'exec "$0"' "$1"
    else
        timeout -k 10 "$SCRIPT_TIMEOUT" /system/bin/sh -c 'exec "$0"' "$1"
    fi
}

umask 022
n=0
for f in "$DIR"/*; do
    [ -f "$f" ] && [ -x "$f" ] || continue
    name=${f##*/}
    say "running $name"
    run_script "$f" </dev/null >>"$LOG" 2>&1
    rc=$?
    if [ $rc -eq 124 ] || [ $rc -eq 137 ]; then
        say "$name: killed after ${SCRIPT_TIMEOUT}s"
    else
        say "$name: exit $rc"
    fi
    n=$((n + 1))
done
say "done: $n script(s)"

# Stay alive (see above).
while :; do sleep 86400; done
