#!/usr/bin/env bash
# See the one-time upgrade notes exactly as a user upgrading will.
#
#   scripts/upgrade-preview.sh            # as if upgrading from 0.4.3
#   scripts/upgrade-preview.sh 0.5.0      # from another version
#
# Builds this checkout stamped with the newest version in
# crates/vortix/src/whats_new.rs (a throwaway copy; nothing here changes),
# and makes an empty scratch config directory that looks as if the older
# version last ran there. No profiles, no keys, no VPN, no firewall change.
set -eu
cd "$(dirname "$0")/.."
FROM=${1:-0.4.3}
TO=$(grep -m1 -oE 'version: "[0-9]+\.[0-9]+\.[0-9]+"' crates/vortix/src/whats_new.rs | grep -oE '[0-9.]+')
WORK=target/upgrade-preview

echo "== building Vortix $TO from $(git rev-parse --short HEAD)"
git worktree remove -f "$WORK/src" 2>/dev/null || true
git worktree add -f --detach "$WORK/src" HEAD >/dev/null
# The crate takes its version from the workspace root.
perl -pi -e 'if (!$done && s/^version = "[^"]+"/version = "'"$TO"'"/) { $done = 1 }' "$WORK/src/Cargo.toml"
CARGO_TARGET_DIR=$PWD/$WORK/target cargo build -q --manifest-path "$WORK/src/Cargo.toml" -p vortix
BIN=$PWD/$WORK/target/debug/vortix
"$BIN" --version

DIR=$(mktemp -d "${TMPDIR:-/tmp}/vortix-upgrade-preview.XXXXXX")
chmod 700 "$DIR"
echo "$FROM" >"$DIR/state-version"

echo
echo "== what the CLI prints on the first run after upgrading from $FROM"
"$BIN" -C "$DIR" list || true

cat <<EOF

== now see the dashboard popup (needs root, like any 'sudo vortix'):

   sudo $BIN -C $DIR

Check:
  1. The popup opens first. If there are steps for this OS, the border is red
     and the title says "Action needed".
  2. Esc, Enter and q do NOT close it; they show a reminder. Only y closes it.
  3. Quit with Ctrl-C before pressing y and run the command again: it is back.
  4. Press y, quit, run it again: no popup (the version is now recorded).
  5. Reset to try again:  echo $FROM | sudo tee $DIR/state-version

Clean up when done:  sudo rm -rf $DIR; git worktree remove -f $WORK/src
EOF
