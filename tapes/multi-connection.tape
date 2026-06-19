# vortix — multi-connection demo
#
# Two tunnels live simultaneously. The hero promise of "vortix handles multiple
# concurrent VPN connections" needs a visual; this is that visual.
#
# Records ~40 s; output lands at assets/multi-connection.gif.
#
# Prerequisites:
#   ./scripts/test-infra.sh up wg-full wg-split
#   ./scripts/test-infra.sh import
#   sudo NOPASSWD configured for vortix (see README).
#   vhs tapes/multi-connection.tape

Output assets/multi-connection.gif

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

# Open on the disconnected dashboard
Sleep 2s

# === First tunnel: wg-full ===
# Profiles sort alphabetically: ovpn-totp / wg-dns-leak / wg-full / wg-split.
# Two Downs from the top lands on wg-full.
Down
Sleep 500ms
Down
Sleep 800ms
Enter
Sleep 12s

# Breath — header green, throughput populating
Sleep 3s

# === Second tunnel: wg-split (secondary) ===
# One more Down lands on wg-split. Enter triggers vortix's takeover overlay;
# `B` ("Both") brings up the second tunnel alongside the first.
Down
Sleep 800ms
Enter
Sleep 1500ms
# `B` = Both — keeps the first tunnel up, adds the second
Type "B"
Sleep 12s

# === Both tunnels visible ===
# Sidebar shows two Connected rows. Chart shows aggregate throughput.
# Hold the beat — this is the differentiating frame.
Sleep 5s

# Cycle Connection Details between the two tunnels by moving sidebar selection
Up
Sleep 2s
Down
Sleep 2s

# === Tear it all down ===
# Shift+D = Disconnect ALL active tunnels (with confirm when N > 1)
Type "D"
Sleep 1500ms
Enter
Sleep 4s

Sleep 1500ms

Hide
Type "q"
