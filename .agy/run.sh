#!/usr/bin/env bash
# Usage: .agy/run.sh <prompt-file> [log-file] [tier]
# Runs Antigravity in print mode from the repo root, falling back across models on capacity
# or quota errors. The tier picks the models (AGY_MODELS="m1 m2 ..." overrides it):
#   light     docs, translations, mechanical edits (Neon medium)
#   standard  app and UI code, tests, scripts (Neon high, default)
#   hard      security-critical or low-level code: WFP, packet handling, policy, crypto glue (Neon xhigh)
#   claude    when Neon is not enough (repeated non-compiling output, subtle concurrency or
#             security work): Claude Opus 5.5 high, then Sonnet 5.5 high, then Neon xhigh.
# Every model's quota group is checked first with .agy/check.sh (agy /usage), and skipped
# when its weekly or five-hour limit is below AGY_MIN_PCT percent remaining.
# AGY_EFFORT (low|medium|high|xhigh|max) sets the reasoning effort when given.
set -u
root="$(cd "$(dirname "$0")/.." && pwd)"
prompt_file="$1"; log="${2:-/tmp/claude-1000/agy-$(basename "$prompt_file").log}"; tier="${3:-standard}"
case "$tier" in
  light)    models="gemini-4-neon-medium gemini-4-neon-high gemini-4-neon-low" ;;
  standard) models="gemini-4-neon-high gemini-4-neon-medium gemini-4-neon-xhigh" ;;
  hard)     models="gemini-4-neon-xhigh gemini-4-neon-high" ;;
  claude)   models="claude-opus-5-5-high claude-sonnet-5-5-high gemini-4-neon-xhigh" ;;
  *) echo "agy: unknown tier $tier (light|standard|hard|claude)" >&2; exit 2 ;;
esac
models="${AGY_MODELS:-$models}"
effort=()
[ -n "${AGY_EFFORT:-}" ] && effort=(--effort "$AGY_EFFORT")
mkdir -p "$(dirname "$log")"
cd "$root"
for model in $models; do
  # Quota check from agy's /usage for the model's group (AGY_MIN_PCT, default 10 %).
  if ! "$root/.agy/check.sh" "$model" >&2; then continue; fi
  agy -p "$(cat "$prompt_file")" --model "$model" "${effort[@]}" --mode accept-edits --sandbox --settings .agy/settings.json >"$log" 2>&1
  if grep -qiE "code 503|code 429|No capacity available|quota exceeded|RESOURCE_EXHAUSTED|unknown model|model not found" "$log"; then
    echo "agy: $model unavailable, trying next" >&2; sleep 20; continue
  fi
  echo "agy: done with $model, tier $tier (log: $log)"; exit 0
done
echo "agy: all models unavailable for tier $tier (log: $log)" >&2; exit 1
