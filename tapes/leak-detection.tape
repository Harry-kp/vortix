# vortix — leak detection demo
#
# The headline differentiator: connect to a misconfigured VPN whose DNS escapes
# the tunnel; Security Guard catches it with a red row in real time. This is
# what every other VPN TUI is missing.
#
# Records ~25 s; output lands at assets/leak-detection.gif.
#
# Prerequisites:
#   ./scripts/test-infra.sh up wg-dns-leak
#   ./scripts/test-infra.sh import
#   sudo NOPASSWD configured for vortix (see README).
#   vhs tapes/leak-detection.tape

Output assets/leak-detection.gif

Set Theme "Catppuccin Mocha"
Set FontSize 16
Set Width 1600
Set Height 900
Set Padding 40

Hide
Type "echo $SUDO_PASSWORD | sudo -S vortix"
Enter
Sleep 4s
Show

Sleep 2s

# Navigate to the wg-dns-leak profile (assumes it's a few rows down — adjust if needed)
Down
Sleep 600ms
Down
Sleep 600ms
Down
Sleep 1500ms

# Connect — the kernel routes everything-except-DNS through the tunnel,
# so DNS queries leak to the system resolver
Enter
Sleep 12s

# Header turns green ("Connected") but vortix's recursor-IP probe will fire and detect
# DNS escape. Give it a beat for the probe cycle.
Sleep 4s

# Tab to Security Guard — the climax of this clip.
# Goal: land on the panel and let the red DNS-leak row sit on screen.
Tab
Sleep 1500ms
Tab
Sleep 1500ms
# Hold on Security Guard so viewers can read the red row
Sleep 5s

# Optional: cycle kill switch to vpn-only to demonstrate sealing the leak
Type "K"
Sleep 3s

# Disconnect
Type "d"
Sleep 4s

Sleep 1500ms

Hide
Type "q"
