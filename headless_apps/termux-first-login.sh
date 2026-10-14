# Installed into Termux's $PREFIX/etc/profile.d by the headless ROM (20-termux).
# While Termux's password is still the ROM's default ("changeme"), an
# interactive SSH login must set a new one before it gets a shell.
_headless_default=/system/etc/headless/termux_default_authinfo
if [ -n "$SSH_CONNECTION" ] && [ -t 0 ] && [ -f "$_headless_default" ] &&
    /system/bin/cmp -s "$HOME/.termux_authinfo" "$_headless_default"; then
    echo "The password is still the default one. Set a new password now."
    _headless_tries=0
    while /system/bin/cmp -s "$HOME/.termux_authinfo" "$_headless_default"; do
        _headless_tries=$((_headless_tries + 1))
        if [ $_headless_tries -gt 3 ]; then
            echo "No new password set, logging out."
            exit 1
        fi
        passwd || continue
        /system/bin/cmp -s "$HOME/.termux_authinfo" "$_headless_default" &&
            echo "That is the default password again. Choose a different one."
    done
    echo "Password changed."
fi
unset _headless_default _headless_tries
