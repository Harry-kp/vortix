# vortix — NetBird
#
# From an empty dashboard: add a NetBird network, sign in, see its peers and
# routes (direct or relayed, latency), and read NetBird's own log.
#
# Prerequisites (one-time setup before recording):
#   1. NetBird's `netbird` command installed on the recording machine.
#   2. A NetBird network with at least one online peer.
#   3. /tmp/vortix-bg.png is the backdrop, /tmp/vortix-demo-rc.sh sets the prompt
#      and `sudo vortix`, and
#      /tmp/vortix-demo-launch.sh starts `sudo vortix -C <an empty config>`
#      without a password prompt (the launch is hidden either way).
#   4. Someone ready to sign in: Vortix opens the sign-in page in the
#      recording machine's browser, and the tape waits up to 5 min, off
#      camera, for the network to connect.
#   5. Render the tape (vhs tapes/netbird.tape), then make the GIF (below).

# The MP4 is for X and other sites; the README GIF is made from it without
# dithering, which keeps the text sharp:
#   ffmpeg -i target/netbird.mp4 -vf "fps=15,scale=1600:-1:flags=lanczos,split[a][b];[a]palettegen=stats_mode=diff[p];[b][p]paletteuse=dither=none" assets/netbird.gif
Output target/netbird.mp4

Set Shell "bash"
Set Theme "Catppuccin Mocha"
Set FontSize 30
Set Width 1920
Set Height 1080
Set Padding 30
Set Margin 40
Set MarginFill "/tmp/vortix-bg.png"
Set WindowBar Colorful
Set WindowBarSize 44
Set BorderRadius 14
Set Framerate 60
Set PlaybackSpeed 1.4

# --- shell setup (hidden) ---
Hide
Type "source /tmp/vortix-demo-rc.sh"
Enter
Sleep 800ms

# --- `sudo vortix`, typed ---
Type "clear"
Enter
Sleep 500ms
Show
Sleep 600ms
Type@110ms "sudo vortix"
Sleep 500ms
Enter
Sleep 5s

# === Act 1 — an empty dashboard ===
Sleep 3s

# === Act 2 — Add a VPN: type `netbird` ===
Type "i"
Sleep 3s
Type@150ms "netbird"
Sleep 1500ms
Enter
Sleep 4s

# === Act 3 — connect: the sign-in dialog opens the browser ===
Type "c"
Sleep 10s

# Signing in happens in the browser, off camera.
Hide
Wait+Screen@5m /MESH/
Sleep 6s
Show

# === Act 4 — connected ===
Sleep 3s

# === Act 5 — routes and peers on the back of Details ===
# Panels cycle Profiles → Chart → Details.
Tab
Sleep 600ms
Tab
Sleep 1500ms
Type "f"
Sleep 4s
# Zoom for the full columns: direct or relayed, latency.
Type "z"
Sleep 7s
Type "z"
Sleep 1500ms
Type "f"
Sleep 1500ms

# === Act 6 — NetBird's own log in the Logs panel ===
Tab
Sleep 600ms
Tab
Sleep 1200ms
# `f` steps the source: errors, warnings, info, then NetBird's own log.
Type@350ms "ffff"
Sleep 2s
Type "z"
Sleep 6s
Type "z"
Sleep 1500ms

# === Final closing shot ===
Escape
Sleep 3s

Hide
Type "q"
