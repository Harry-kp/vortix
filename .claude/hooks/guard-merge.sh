#!/usr/bin/env bash
# PreToolUse guard for Bash: Claude never merges a release or proposal PR, and never merges
# with --auto or --admin. Those merges are the maintainer's. Exit 2 blocks the call.
cmd=$(jq -r '.tool_input.command // empty')
[[ $cmd == *"gh pr merge"* ]] || exit 0
if [[ $cmd == *--auto* || $cmd == *--admin* ]]; then
    echo "Blocked: no --auto or --admin merges; merge only after every check passes." >&2
    exit 2
fi
ref=$(sed -E 's/.*gh pr merge//' <<<"$cmd" | tr ' ' '\n' | grep -v '^-' | grep -m1 -E '^[0-9]+$|^https://')
if ! labels=$(gh pr view $ref --json labels -q '.labels[].name' 2>/dev/null); then
    echo "Blocked: could not read the PR's labels, so the merge is not allowed." >&2
    exit 2
fi
if grep -qxE 'release|proposal' <<<"$labels"; then
    echo "Blocked: PRs labelled release or proposal are merged by the maintainer only." >&2
    exit 2
fi
exit 0
