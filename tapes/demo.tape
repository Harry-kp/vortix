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
Set FontSize 20
Set Width 1920
Set Height 1080
Set Padding 50
Set Framerate 60
Set PlaybackSpeed 1.4

# --- launch (hidden so any "Password:" prompt is never recorded) ---
Hide
Type "/tmp/vortix-demo-launch.sh"
Enter
Sleep 4s
Show

# === Act 1 — open on the disconnected dashboard ===
Sleep 2s

# === Act 2 — profile sidebar tour ===
# Cursor starts on the alphabetically-first profile (ovpn-totp). Walk down
# through the list — three Downs land on wg-split, the last entry.
Down
Sleep 900ms
Down
Sleep 900ms
Down
Sleep 1200ms

# === Act 3 — peek at the highlighted profile's config ===
Type "v"
Sleep 3s
Escape
Sleep 1200ms

# === Act 5 — connect to wg-full ===
# Up once from wg-split lands on wg-full (the natural full-tunnel headline).
Up
Sleep 1200ms
Enter
Sleep 12s

# === Act 5 — connected breath ===
# Header is green; IP + geo-location have rotated; throughput chart is filling.
Sleep 3s

# === Act 6 — sort cycle flash (post-connect — purely visual, tunnel unaffected) ===
# `s` cycles ProfileSortOrder. One press shows the sidebar reflowing without
# disturbing the active tunnel (cursor stays on wg-full through the reorder).
Type "s"
Sleep 1800ms

# === Act 7 — flip Chart panel (round trip) ===
Tab
Sleep 1200ms
Type "f"
Sleep 2500ms
Type "f"
Sleep 1500ms

# === Act 9 — flip Connection Details (round trip) + zoom ===
Tab
Sleep 1200ms
Type "f"
Sleep 2500ms
Type "f"
Sleep 1500ms
# Zoom — `z` expands the focused panel to full-frame, `z` again collapses.
Type "z"
Sleep 2500ms
Type "z"
Sleep 1500ms

# === Act 10 — Security Guard, the centrepiece (round trip) ===
# IPv4 + IPv6 dual-stack identity rows, recursor-IP DNS leak probe, kill-switch row.
# Hold the front face longer — it's the headline. Then flip + flip back.
Tab
Sleep 4s
Type "f"
Sleep 2500ms
Type "f"
Sleep 1500ms

# === Act 11 — log filter cycle ===
# Tab to the Event Log panel; `f` here cycles the log filter overlay.
Tab
Sleep 1200ms
Type "f"
Sleep 1500ms
Type "f"
Sleep 1500ms
# Dismiss the filter overlay so the action menu doesn't stack on top of it.
Escape
Sleep 800ms

# === Act 12 — action menu flash ===
# `x` opens the contextual action menu; `x` again toggles it closed (the
# overlay handler accepts `x`, `q`, `b`, or Esc as dismiss — using `x`
# avoids vhs's Escape racing the terminal parser's ANSI-sequence timeout).
Type "x"
Sleep 2500ms
Type "x"
Sleep 1200ms

# === Act 13 — disconnect everything ===
# Shift+D disconnects ALL active tunnels regardless of which panel is focused.
# Safer than `d` (which acts on the focused tunnel and depends on panel context).
Type "D"
Sleep 1200ms
# If a "disconnect all (N>1)" confirm dialog appears, Enter accepts it. With one
# tunnel up this is a no-op but harmless.
Enter
Sleep 5s

# === Act 14 — help overlay + tab through its sections (closing reference) ===
# Show the full keymap LAST — viewers have seen what the tool does; this is
# the "here's how to reach everything" closing beat. Tab cycles help sections.
Type "?"
Sleep 2000ms
Tab
Sleep 1500ms
Tab
Sleep 1500ms
Tab
Sleep 1500ms
Escape
Sleep 1200ms

# === Final closing shot ===
Sleep 2s

Hide
Type "q"
