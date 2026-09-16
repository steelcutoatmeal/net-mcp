#!/bin/sh
# PostToolUse hook: run ruff format on a Python file Claude just edited.
# Input is the hook JSON on stdin; we only need tool_input.file_path.
FILE=$(python3 -c '
import json, sys
try:
    path = json.load(sys.stdin).get("tool_input", {}).get("file_path", "")
except Exception:
    path = ""
if path.endswith(".py"):
    print(path)
')
[ -n "$FILE" ] || exit 0
cd "${CLAUDE_PROJECT_DIR:-.}" && uv run --quiet ruff format --quiet "$FILE" 2>/dev/null || true
exit 0
