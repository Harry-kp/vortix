# vortix — profile management demo
#
# CRUD on profiles, all from the TUI: import (`i`), rename (action menu),
# delete (`Del`), and sort cycle (`s`). Shows that vortix is a complete
# manager, not just a connection runner.
#
# Records ~30 s; output lands at assets/profile-management.gif.
#
# Prerequisites:
#   At least 2-3 profiles already present in vortix (any flavors will do).
#   A spare profile file at /tmp/extra.conf to import (any valid .conf or .ovpn).
#     e.g. cp scripts/test-profiles/wg-split.conf /tmp/extra.conf
#   sudo NOPASSWD configured for vortix (see README).
#   vhs tapes/profile-management.tape

Output assets/profile-management.gif

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

# === Import a new profile ===
# `i` opens the import overlay. Type a path; Enter confirms.
Type "i"
Sleep 2s
Type "/tmp/extra.conf"
Sleep 1500ms
Enter
Sleep 3s

# === Rename via the action menu ===
# Select the just-imported profile, then `x` for action menu → Rename
Down
Sleep 800ms
Type "x"
Sleep 1500ms
# Action menu — pick Rename (one Down then Enter, adjust if menu order differs)
Down
Sleep 800ms
Enter
Sleep 1500ms
# Rename input — type a new name
Type "renamed-demo"
Sleep 1500ms
Enter
Sleep 2500ms

# === Sort cycle ===
# `s` cycles ProfileSortOrder. Sidebar reflows after each press.
Type "s"
Sleep 1500ms
Type "s"
Sleep 1500ms
Type "s"
Sleep 1500ms

# === Delete a profile ===
# `Del` on the highlighted profile opens a confirm overlay
Down
Sleep 800ms
Delete
Sleep 1500ms
# Confirm — Enter on the default Yes button
Enter
Sleep 2500ms

Sleep 1500ms

Hide
Type "q"
