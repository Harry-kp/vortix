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

# === Import a new profile ===
# `i` opens the import overlay. Type a path; Enter confirms.
Type "i"
Sleep 2s
Type "/tmp/extra.conf"
Sleep 1500ms
Enter
Sleep 3s

# === Rename via the action menu ===
# vhs sends "R" as Char('r') + SHIFT modifier; vortix's direct rename matches
# only Char('R') without modifiers, so the direct shortcut won't fire under vhs.
# Workaround: open the action menu and Up-wrap to "Rename Profile".
# The Sidebar menu has 10 items: Import / Connect / Reconnect / ViewConfig /
# EditAuth / ClearAuth / Delete / Sort / Rename / ToggleZoom (last). Up wraps
# from item 1 to item 10; Up Up lands on item 9 (Rename Profile).
Type "x"
Sleep 1500ms
Up
Sleep 500ms
Up
Sleep 800ms
Enter
Sleep 1500ms
# Now in rename input — pre-populated with the current name "extra" (5 chars).
# Clear it before typing the new name, otherwise the typed string is appended.
Backspace 5
Sleep 500ms
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

# === Delete the renamed demo profile ===
# After the sort cycle the cursor is still on the renamed profile (rename
# preserves selection through sort changes). `Delete` opens the confirm overlay.
Delete
Sleep 1500ms
# Confirm with `y` — the dialog defaults focus to [No] so Enter would cancel;
# `y` always commits regardless of which button is currently highlighted.
Type "y"
Sleep 2500ms

Sleep 1500ms

Hide
Type "q"
