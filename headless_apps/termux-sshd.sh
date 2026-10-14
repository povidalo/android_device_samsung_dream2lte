#!/system/bin/sh
# Started by the headless ROM boot script 20-termux, as root, with the Termux
# user id as $1: install openssh in Termux once the network is up, then keep
# sshd running as the Termux user (port 8022, key login).

TU=$1
T=/data/data/com.termux
P=$T/files/usr
H=$T/files/home
LOG=/data/local/termux-setup.log

log() { echo "$(date '+%F %T') $*" >>"$LOG"; }

# Run a command line as the Termux user with Termux's environment.
as_termux() {
    pre=
    for l in libtermux-exec-ld-preload.so libtermux-exec.so; do
        if [ -f "$P/lib/$l" ]; then pre=$P/lib/$l; break; fi
    done
    su "$TU" -c "export PREFIX=$P HOME=$H TMPDIR=$P/tmp LANG=en_US.UTF-8 PATH=$P/bin:/system/bin${pre:+ LD_PRELOAD=$pre}; cd $H; $*"
}

[ -f "$LOG" ] && tail -n 400 "$LOG" >"$LOG.tmp" && mv -f "$LOG.tmp" "$LOG"
log "supervisor started (Termux uid $TU)"

tries=0
while [ ! -x "$P/bin/sshd" ]; do
    tries=$((tries + 1))
    log "installing openssh (attempt $tries)"
    if as_termux "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y install openssh" >>"$LOG" 2>&1; then
        log "openssh installed"
        break
    fi
    sleep 60
done

while :; do
    if ! pidof sshd >/dev/null; then
        log "starting sshd"
        as_termux sshd >>"$LOG" 2>&1 || log "sshd failed to start"
    fi
    sleep 30
done
