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
Set FontSize 16
Set Width 1600
Set Height 900
Set Padding 40

Hide
Type "echo $SUDO_PASSWORD | sudo -S vortix"
Enter
Sleep 4s
Show

Sleep 2s

# Navigate to wg-split — adjust the Down count to match your sidebar order
Down
Sleep 600ms
Down
Sleep 1500ms

# Connect — handshake completes quickly for split-tunnel WG
Enter
Sleep 10s

# Tab to Connection Details — this is where AllowedIPs / routing scope is shown
Tab
Sleep 3500ms

# Flip the panel for any expanded routing/MTU view
Type "f"
Sleep 3500ms

# Disconnect
Type "d"
Sleep 4s

Sleep 1500ms

Hide
Type "q"
