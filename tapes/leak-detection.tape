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

Sleep 2s

# Profiles sort alphabetically: ovpn-totp / wg-dns-leak / wg-full / wg-split.
# One Down from the top lands on wg-dns-leak.
Down
Sleep 1500ms

# Connect — the kernel routes everything-except-DNS through the tunnel,
# so DNS queries leak to the system resolver.
Enter
Sleep 12s

# Header turns green ("Connected") but vortix's recursor-IP probe runs on its
# own polling cadence (~15s post-handshake) before the DNS-leak row turns red.
# Hold longer here than feels natural — the leak detection IS the headline.
Sleep 15s

# Tab to Security Guard. Goal: land on the panel and let the red DNS-leak row
# sit on screen long enough to read.
Tab
Sleep 1500ms
Tab
Sleep 1500ms
# Hold on Security Guard front face — bumped from 5s to 8s so the red row
# is on screen long enough to register.
Sleep 8s

# Flip Security Guard back face (round trip) to surface the connection audit
Type "f"
Sleep 2500ms
Type "f"
Sleep 1500ms

# Disconnect everything (focus-independent, won't be eaten by overlay focus)
Type "D"
Sleep 1200ms
Enter
Sleep 4s

Sleep 1500ms

Hide
Type "q"
