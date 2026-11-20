#!/usr/bin/env bash
# Usage: .agy/run.sh <prompt-file> [log-file]
# Runs Antigravity in print mode from the repo root, falling back across models on capacity errors (503).
set -u
root="$(cd "$(dirname "$0")/.." && pwd)"
prompt_file="$1"; log="${2:-/tmp/claude-1000/agy-$(basename "$prompt_file").log}"
mkdir -p "$(dirname "$log")"
cd "$root"
for model in gemini-3.8-flash-medium gemini-3.8-flash-high gemini-3.8-flash-low gemini-3.8-flash-medium; do
  agy -p "$(cat "$prompt_file")" --model "$model" --mode accept-edits --sandbox --settings .agy/settings.json >"$log" 2>&1
  if grep -q "code 503\|No capacity available" "$log"; then
    echo "agy: $model unavailable, trying next" >&2; sleep 20; continue
  fi
  echo "agy: done with $model (log: $log)"; exit 0
done
echo "agy: all models unavailable (log: $log)" >&2; exit 1
