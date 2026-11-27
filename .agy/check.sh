#!/usr/bin/env bash
# Usage: .agy/check.sh <model>
# Checks the model's quota group with agy's /usage (weekly and five-hour limits) and exits 0
# when both are at or above AGY_MIN_PCT percent remaining (default 10), 1 otherwise.
# Without a /usage answer it falls back to a one-word prompt.
set -u
model="$1"; min="${AGY_MIN_PCT:-10}"
case "$model" in
  claude-*|gpt-*) group="Claude and GPT models" ;;
  *)              group="Gemini Models" ;;
esac
usage="$(agy -p "/usage" --print-timeout 60s 2>&1)"
lines="$(printf '%s\n' "$usage" | grep -F "$group" | grep -E "Limit Remaining")"
if [ -n "$lines" ]; then
  ok=1
  while IFS=$'\t' read -r _ what pct reset; do
    p="${pct%\%}"
    echo "agy-check: $group $what $pct (resets $reset)"
    if [ "${p:-0}" -lt "$min" ] 2>/dev/null; then ok=0; fi
  done <<<"$lines"
  [ "$ok" = 1 ] && exit 0
  echo "agy-check: $model below ${min}% remaining, skipping"; exit 1
fi
out="$(agy -p "Reply with the single word OK." --model "$model" --mode accept-edits --sandbox --settings "$(dirname "$0")/settings.json" --print-timeout 90s 2>&1)"
if echo "$out" | grep -qiE "code 503|code 429|No capacity available|quota exceeded|RESOURCE_EXHAUSTED|rate limit|unknown model|model not found"; then
  echo "agy-check: $model not usable"; exit 1
fi
echo "agy-check: $model answered (no /usage data)"; exit 0
