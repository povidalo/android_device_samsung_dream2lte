# headless_su: Termux (an app uid, not in group shell) must be able to reach and
# run /system/xbin/su. AOSP's built-in fs_config makes system/xbin 0750 root:shell
# and system/xbin/su 04750 root:shell (setuid, shell group only); these entries
# take precedence. No setuid: every non-root caller, adb shell included, goes
# through the sud daemon and its password.
[system/xbin/]
mode: 0755
user: AID_ROOT
group: AID_SHELL
caps: 0

[system/xbin/su]
mode: 0755
user: AID_ROOT
group: AID_SHELL
caps: 0
