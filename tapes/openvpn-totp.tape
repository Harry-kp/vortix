# vortix — OpenVPN + TOTP auth demo
#
# Connects to an OpenVPN profile with username + password + TOTP (static-challenge
# SCRV1). The auth overlay appears, gets filled in, the handshake completes.
# Shows that vortix handles non-trivial OpenVPN auth — not just "drop in a config".
#
# Records ~30 s; output lands at assets/openvpn-totp.gif.
#
# Prerequisites:
#   ./scripts/vpn-lab.sh up
#   Copy 04-openvpn-tcp-static-challenge.ovpn to ovpn-totp.ovpn in the clean
#   demo profile directory and import it into vortix.
#   sudo NOPASSWD configured for vortix (see README).
#   The generated credentials.txt supplies the fixed isolated-lab values:
#   username `vortix`, password `vortix-pass`, static challenge `123456`.
#
#   vhs tapes/openvpn-totp.tape

Output assets/openvpn-totp.gif

Set Theme "Catppuccin Mocha"
Set FontSize 20
Set Width 1920
Set Height 1080
Set Padding 50
Set Framerate 60
Set PlaybackSpeed 1.4

Hide
Type "/tmp/vortix-demo-launch.sh"
Enter
Sleep 4s
Show

Sleep 1500ms

# Profiles sort alphabetically: ovpn-totp is already at the top — no Down needed.
Sleep 800ms

# Connect — vortix detects the static-challenge profile and opens the auth overlay.
# This tape assumes /tmp/vortix-demo-config/auth/ovpn-totp.auth does NOT exist
# at record time (clear it before running if needed). With no saved creds,
# vortix sets initial focus to Username (per connection.rs:242), so the
# Tab order is: Username → Password → OTP → SaveCheckbox → Username.
Enter
Sleep 1500ms

# Username field
Type "vortix"
Sleep 500ms
Tab
Sleep 300ms

# Password field
Type "vortix-pass"
Sleep 500ms
Tab
Sleep 300ms

# Static challenge accepted only by the ephemeral lab's profile 04.
Type "123456"
Sleep 400ms

# Submit
Enter

# Real OpenVPN handshake — slower than WireGuard. Be generous.
Sleep 15s

# Connected. Brief breath on the dashboard.
Sleep 3s

# Disconnect everything (focus-independent, safe with overlays open)
Type "D"
Sleep 1200ms
Enter
Sleep 4s

Sleep 1500ms

Hide
Type "q"
