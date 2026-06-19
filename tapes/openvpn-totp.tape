# vortix — OpenVPN + TOTP auth demo
#
# Connects to an OpenVPN profile with username + password + TOTP (static-challenge
# SCRV1). The auth overlay appears, gets filled in, the handshake completes.
# Shows that vortix handles non-trivial OpenVPN auth — not just "drop in a config".
#
# Records ~30 s; output lands at assets/openvpn-totp.gif.
#
# Prerequisites:
#   ./scripts/test-infra.sh up ovpn-totp
#   ./scripts/test-infra.sh import
#   sudo NOPASSWD configured for vortix (see README).
#   A working TOTP code for the test profile. The test-infra script provisions
#   a known secret per droplet; generate the current code with:
#     oathtool --totp --base32 "$(./scripts/test-infra.sh totp-secret ovpn-totp)"
#   Substitute the 6-digit code into the Type "123456" line below before running.
#
#   vhs tapes/openvpn-totp.tape

Output assets/openvpn-totp.gif

Set Theme "Catppuccin Mocha"
Set FontSize 16
Set Width 1600
Set Height 900
Set Padding 40

Hide
Type "sudo vortix"
Enter
Sleep 4s
Show

Sleep 2s

# Navigate to the ovpn-totp profile
Down
Sleep 500ms
Down
Sleep 500ms
Down
Sleep 500ms
Down
Sleep 500ms
Down
Sleep 1500ms

# Connect — vortix detects the static-challenge profile and opens the auth overlay
Enter
Sleep 2500ms

# Username field
Type "vortix-demo"
Sleep 1500ms
Tab
Sleep 800ms

# Password field
Type "demo-password"
Sleep 1500ms
Tab
Sleep 800ms

# TOTP code field — replace with a current code before recording
Type "123456"
Sleep 1500ms

# Submit
Enter

# Real OpenVPN handshake — slower than WireGuard. Be generous.
Sleep 15s

# Connected. Brief breath on the dashboard.
Sleep 3s

# Disconnect
Type "d"
Sleep 4s

Sleep 1500ms

Hide
Type "q"
