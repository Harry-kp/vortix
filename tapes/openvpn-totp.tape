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
#   a per-droplet secret; read it from
#   scripts/test-profiles/ovpn-totp-credentials.txt after `./scripts/test-infra.sh profiles`,
#   then generate a current code:
#     oathtool --totp -b "$(awk '/totp_secret:/ {print $2}' scripts/test-profiles/ovpn-totp-credentials.txt)"
#   Substitute the 6-digit code into the Type "000000" line below before running.
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
Type "testpass123"
Sleep 500ms
Tab
Sleep 300ms

# OTP / TOTP code — populated at record time by the orchestrator (run
# `oathtool` against the per-droplet secret extracted from
# scripts/test-profiles/ovpn-totp-credentials.txt). The literal in the
# tape is a placeholder; replace with a current code via sed before vhs.
Type "000000"
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
