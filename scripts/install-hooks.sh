#!/bin/bash

# Installation script for Vortix git hooks

HOOK_SRC="scripts/pre-commit.sh"
HOOK_DEST=".git/hooks/pre-commit"

if [ ! -f "$HOOK_SRC" ]; then
    echo "❌ Error: $HOOK_SRC not found. Run this from the project root."
    exit 1
fi

if [ ! -d ".git" ]; then
    echo "❌ Error: .git directory not found. Are you in the project root?"
    exit 1
fi

echo "⚙️  Installing pre-commit hook..."
# A link, not a copy: an edit to the script takes effect without reinstalling.
chmod +x "$HOOK_SRC"
ln -sf "../../$HOOK_SRC" "$HOOK_DEST"

echo "✅ Pre-commit hook installed successfully!"
