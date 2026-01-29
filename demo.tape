# Vortix VPN Manager - Marketing Demo Script
# Professional demo showcasing all key features
# Run with: vhs demo.tape

Output demo.gif

Set Shell "zsh"
Set FontSize 18
Set Width 1920
Set Height 1080
Set Theme "nord"
Set Padding 40

Hide
# Clear screen and show startup
Type "sudo cargo run -- --demo"
Sleep 1s
Enter
Sleep 1.5s

# Hide password input for security
Type "lorem ipsum"
Sleep 500ms
Enter
Show

# Wait for application to start
Sleep 5s

# Let initial state load completely
Sleep 2.5s

# === SECTION 1: Overview - Show the beautiful interface ===
# Profile list is visible by default
Sleep 2s

# Demonstrate profile navigation (key feature)
Type "g"
Sleep 1.2s
Down
Sleep 800ms
Down
Sleep 800ms
Type "G"
Sleep 1.2s

# === SECTION 2: Config Viewer ===
# Show detailed config inspection (unique feature)
Type "v"
Sleep 2.5s
Down
Sleep 700ms
Down
Sleep 700ms
Down
Sleep 700ms
Down
Sleep 700ms
Type "G"
Sleep 1.5s
Type "g"
Sleep 1s
Escape
Sleep 1.5s

# === SECTION 3: Panel Navigation - Show all panels ===
# Navigate through all panels to show comprehensive dashboard
Tab
Sleep 2s
Tab
Sleep 2s
Tab
Sleep 2s
Tab
Sleep 2s
Tab
Sleep 2s

# Return to Profiles
Tab
Sleep 1.5s

# === SECTION 4: Connection Details Panel ===
# Show telemetry data (impressive feature)
Tab
Sleep 2.5s

# === SECTION 5: Real-time Throughput Chart ===
# Show live network monitoring (key selling point)
Tab
Sleep 3s

# === SECTION 6: Security Panel ===
# Highlight security features (kill switch, leak detection)
Tab
Sleep 3s

# === SECTION 7: Activity Logs ===
# Show comprehensive logging
Tab
Sleep 2.5s
Down
Sleep 700ms
Down
Sleep 700ms
Down
Sleep 700ms
Type "g"
Sleep 1s
Type "G"
Sleep 1.2s

# Return to Profiles
Tab
Sleep 1.5s

# === SECTION 8: Advanced Features ===
# Show zoom feature (expert mode)
Type "z"
Sleep 2.5s
Escape
Sleep 1.5s

# Show action menu (contextual actions)
Type "x"
Sleep 2s
Down
Sleep 800ms
Down
Sleep 800ms
Down
Sleep 800ms
Escape
Sleep 1.5s

# Show bulk import menu
Type "b"
Sleep 2s
Escape
Sleep 1.5s

# === SECTION 9: Quick Connect (1-9 slots) ===
# Demonstrate fast profile switching
Type "1"
Sleep 2s

# === SECTION 10: Final Overview ===
# Navigate through panels one final time for complete view
Tab
Sleep 2s
Tab
Sleep 2s
Tab
Sleep 2s
Tab
Sleep 2s
Tab
Sleep 2s

# Return to Profiles panel for clean finish
Tab
Sleep 1.5s

# Final showcase - let viewer see the complete interface
Sleep 3s

# Graceful exit
Type "q"
Sleep 800ms
