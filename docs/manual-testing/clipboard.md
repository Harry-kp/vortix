# Terminal clipboard

OSC 52 acceptance is terminal policy, so a unit test can prove the bytes but not that a real
terminal stores them. Run this on macOS and Linux in the same `tmux` harness as
[`P0.md`](P0.md).

## Copy the displayed IPv4 into the terminal host clipboard

1. Enable tmux clipboard capture, start Vortix, and connect a profile:

   ```bash
   tmux set-option -g set-clipboard on
   tui 80 24
   key c
   sleep 10
   ```

2. Press `y`, capture the success toast, and compare its address with tmux's clipboard buffer:

   ```bash
   key y
   FRAME="$(frame)"
   EXPECTED="$(printf '%s\n' "$FRAME" | sed -nE 's/.*Copied IPv4: ([0-9.]+).*/\1/p' | head -1)"
   ACTUAL="$(tmux show-buffer)"
   test -n "$EXPECTED" && test "$ACTUAL" = "$EXPECTED" && echo "PASS: $ACTUAL"
   ```

**Pass** — the command prints `PASS: <address>`, and the captured frame contains the same
`Copied IPv4: <address>` toast.

**Fail** — no toast, an empty tmux buffer, or different addresses.
