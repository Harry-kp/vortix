# vortix — flagship demo (hero)
#
# Cinematic tour of the connected experience, top to bottom:
# launch → help → profile sidebar → sort → config peek → connect (real handshake)
# → throughput → flip Chart → flip Connection Details → zoom → Security Guard
# → flip Security Guard → log filter → action menu → kill-switch cycle → disconnect.
#
# Records ~70 s; output lands at assets/demo.gif.
#
# Prerequisites (one-time setup before recording):
#   1. Spin up at least one test VPN:        ./scripts/test-infra.sh up wg-full
#   2. Import the profile(s) into vortix:    ./scripts/test-infra.sh import
#   3. Configure sudo NOPASSWD for vortix    (see README "Linux: setting up sudo access")
#      — without this the tape stalls at the password prompt.
#   4. Render the tape:                      vhs tapes/demo.tape
#
# After recording, optionally tear the test infra back down:
#   ./scripts/test-infra.sh down

Output assets/demo.gif

Set Theme "Catppuccin Mocha"
Set FontSize 16
Set Width 1600
Set Height 900
Set Padding 40

# --- launch (hidden so any "Password:" prompt is never recorded) ---
Hide
Type "sudo vortix"
Enter
Sleep 4s
Show

# === Act 1 — open on the disconnected dashboard ===
Sleep 2s

# === Act 2 — help overlay flash ===
# `?` opens the full keymap. Hold long enough to read the highlights, then close.
Type "?"
Sleep 3s
Escape
Sleep 1s

# === Act 3 — profile sidebar tour ===
Down
Sleep 900ms
Down
Sleep 1200ms

# === Act 4 — sort cycle ===
# `s` cycles ProfileSortOrder. One press shows the sidebar reflowing.
Type "s"
Sleep 1800ms

# === Act 5 — peek at the highlighted profile's config ===
Type "v"
Sleep 3s
Escape
Sleep 1200ms

# === Act 6 — connect ===
# Snap to the top profile, hit Enter, real handshake.
Type "g"
Sleep 1200ms
Enter
Sleep 12s

# === Act 7 — connected breath ===
# Header is green; IP + geo-location have rotated; throughput chart is filling.
Sleep 4s

# === Act 8 — flip the Chart panel ===
Tab
Sleep 1200ms
Type "f"
Sleep 3500ms

# === Act 9 — flip Connection Details + zoom ===
Tab
Sleep 1200ms
Type "f"
Sleep 3000ms
# Zoom on the (now-flipped) Connection Details — focus pops to full-frame, then collapses.
Type "z"
Sleep 3000ms
Type "z"
Sleep 1200ms

# === Act 10 — Security Guard, the centrepiece ===
# IPv4 + IPv6 dual-stack identity rows, recursor-IP DNS leak probe, kill-switch row.
# Hold this beat — it's the headline.
Tab
Sleep 4s
Type "f"
Sleep 3500ms

# === Act 11 — log filter ===
# Tab once more to the log panel; `f` here cycles the log filter (info/warn/error/debug).
Tab
Sleep 1200ms
Type "f"
Sleep 1500ms
Type "f"
Sleep 1500ms

# === Act 12 — action menu flash ===
# `x` opens the contextual action menu. Flash open + dismiss.
Type "x"
Sleep 2500ms
Escape
Sleep 1200ms

# === Act 13 — kill switch cycle ===
# Shift+K cycles Off → block-on-drop → vpn-only. Two presses takes the viewer
# from the resting mode through the next one, then back.
Type "K"
Sleep 2500ms
Type "K"
Sleep 2500ms

# === Act 14 — disconnect ===
Type "d"
Sleep 5s

# === Final closing shot ===
Sleep 2s

Hide
Type "q"
