#!/system/bin/sh
# USB-C role watcher, init service headless_usb_role (sud.rc), from early boot.
# After a reboot the S2MM005 USB-C controller can settle in the wrong role and
# stay there until replugged (in Android and TWRP alike): host towards a
# computer (two hosts, nothing works) or device towards a dock (the dock and
# everything behind it stays dark). When the current role does not work for a
# while, re-attach the port in the other role (a software replug): writing
# "sink"/"source" to the Type-C class port_type makes the driver detach and
# re-attach as UFP/DFP. A forced attach that finds no partner times out back
# to dual-role in the driver, and an unplug restores dual-role too, so the port
# cannot get stuck (a plain charger keeps charging). At most two flips until
# the port works for a minute or is unplugged. Log: /data/local/usb-boot.log

TC=/sys/class/typec/port0
LOG=/data/local/usb-boot.log
HOST_GRACE=12   # s as host with no USB device below the root hubs
DEVICE_GRACE=20 # s as device with a partner but no host configuring us

log() { echo "$(date '+%F %T') usb-role: $*" >>"$LOG"; chmod 644 "$LOG"; }
role() { sed -n 's/.*\[\(.*\)\].*/\1/p' "$TC/data_role" 2>/dev/null; } # host | device
partner() { [ -e "$TC/port0-partner" ]; }
devices() { ls /sys/bus/usb/devices | grep -c -E '^[0-9]+-[0-9.]+$'; } # below the root hubs
configured() { [ "$(cat /sys/class/android_usb/android0/state 2>/dev/null)" = CONFIGURED ]; }
gadget_ready() { [ "$(getprop sys.usb.ffs.ready)" = 1 ]; }

[ -w "$TC/port_type" ] || { log "no writable $TC/port_type, watcher not running"; exit 0; }

bad=0 flips=0 calm=0
while :; do
    sleep 3
    r=$(role)
    case $r in
    host) [ "$(devices)" -gt 0 ] && ok=1 || ok=0; grace=$HOST_GRACE ;;
    device)
        if ! partner; then # nothing plugged in (idle also reads "device"): a real unplug
            bad=0 flips=0
            continue
        fi
        gadget_ready || continue # USB gadget not up yet (early boot): cannot judge
        configured && ok=1 || ok=0
        grace=$DEVICE_GRACE
        ;;
    *) continue ;;
    esac
    if [ $ok = 1 ]; then
        bad=0
        calm=$((calm + 3))
        [ $calm -ge 60 ] && flips=0
        continue
    fi
    calm=0
    bad=$((bad + 3))
    [ $bad -ge $grace ] && [ $flips -lt 2 ] || continue
    case $r in host) want=sink ;; *) want=source ;; esac
    flips=$((flips + 1))
    log "port is $r but nothing works for ${bad}s: re-attaching as $want (flip $flips, uptime $(cut -d' ' -f1 /proc/uptime)s)"
    echo $want >"$TC/port_type" 2>/dev/null
    bad=0
done
