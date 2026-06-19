# vortix — split tunnel demo
#
# Connect to a wg-split profile (AllowedIPs limited to 10.8.0.0/24). Connection
# Details surfaces the partial routing scope, distinguishing this from a
# full-tunnel setup at a glance.
#
# Records ~20 s; output lands at assets/split-tunnel.gif.
#
# Prerequisites:
#   ./scripts/test-infra.sh up wg-split
#   ./scripts/test-infra.sh import
#   sudo NOPASSWD configured for vortix (see README).
#   vhs tapes/split-tunnel.tape

Output assets/split-tunnel.gif

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
# Three Downs from the top lands on wg-split.
Down
Sleep 500ms
Down
Sleep 500ms
Down
Sleep 1500ms

# Connect — handshake completes quickly for split-tunnel WG
Enter
Sleep 10s

# Tab to Connection Details — this is where AllowedIPs / routing scope is shown
Tab
Sleep 3500ms

# Flip the panel back face (round trip) for any expanded routing / MTU view
Type "f"
Sleep 2500ms
Type "f"
Sleep 1500ms

# Disconnect everything (focus-independent, safe with overlays open)
Type "D"
Sleep 1200ms
Enter
Sleep 4s

Sleep 1500ms

Hide
Type "q"
