#!/bin/bash
# PostToolUse hook: automatically compile .jazz files after Write/Edit.
# Receives tool use JSON on stdin. Outputs jasminc results for Claude to see.

input=$(cat)

# Extract the file path from the tool input
file_path=$(echo "$input" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(d.get('tool_input', {}).get('file_path', ''))
except Exception:
    print('')
" 2>/dev/null) || file_path=""

# Only process .jazz files (.jinc files are compiled as part of their parent .jazz)
if [[ "$file_path" != *.jazz ]]; then
    exit 0
fi

if [[ ! -f "$file_path" ]]; then
    exit 0
fi

# Check jasminc is available
if ! command -v jasminc &>/dev/null; then
    echo "[jasmin-hook] jasminc not found in PATH — skipping compile check"
    exit 0
fi

echo "[jasmin-hook] Compiling: $file_path"

# Run from the file's directory so relative 'require' paths resolve correctly
dir=$(dirname "$file_path")
base=$(basename "$file_path")

output=$(cd "$dir" && jasminc -arch x86-64 "$base" 2>&1)
rc=$?

if [[ $rc -eq 0 ]]; then
    echo "[jasmin-hook] OK"
else
    echo "[jasmin-hook] ERRORS:"
    echo "$output"
fi

exit 0
