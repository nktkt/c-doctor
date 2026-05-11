#!/usr/bin/env bash
# PostToolUse hook: re-scan a .c/.h file after Claude edits it.
# Prints the c-doctor report only when issues are found (silent on clean files).

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOC="$PROJECT_DIR/target/release/c-doctor"

payload="$(cat)"

file=$(printf '%s' "$payload" | python3 -c '
import json, sys
try:
    print(json.load(sys.stdin).get("tool_input", {}).get("file_path", ""))
except Exception:
    pass
' 2>/dev/null)

case "$file" in
  *.c|*.h) ;;
  *) exit 0 ;;
esac

[ -x "$DOC" ] || exit 0

# --fail-under 100 makes the binary exit 2 if any issue is found.
output="$("$DOC" "$file" --fail-under 100 2>&1)"
status=$?
if [ "$status" -ne 0 ]; then
  printf '\n--- c-doctor (post-edit on %s) ---\n%s\n' "$file" "$output"
fi
exit 0
