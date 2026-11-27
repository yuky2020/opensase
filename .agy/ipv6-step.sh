#!/usr/bin/env bash
# Usage: .agy/ipv6-step.sh <step number> [tier] — runs agy on one step of docs/research/ipv6-gaps.md (#74).
set -u
n="$1"; tier="${2:-hard}"; root="$(cd "$(dirname "$0")/.." && pwd)"
p="$root/.agy/prompts/ipv6-step$n.md"
cat >"$p" <<PROMPT
You work in the repo at the current directory (OpenSASE, Go and shell). Task: implement exactly Step $n of the "Ordered Implementation Plan" in docs/research/ipv6-gaps.md (issue #74, IPv6 end to end). Earlier steps are already done.

Rules: do NOT run any shell command at all; use only your file-read, file-search and file-edit tools; work directly, do not stop after research and do not delegate to subagents. English only in code, comments and docs. Never name commercial companies or products. Do not edit pkg/api/types.go or mobile/api.go; if Step $n needs a contract change, add a // CONTRACT-CHANGE-REQUEST: comment next to your code instead. Touch only the files that Step $n lists, plus their tests.

Read first: CLAUDE.md, the whole of docs/research/ipv6-gaps.md (the step and the sections it refers to, with their file:line evidence), then every file the step lists before editing it.

Do: make the changes Step $n describes and add the proving tests it names (table-driven, in the style of the surrounding tests). Keep behaviour for IPv4 unchanged. Where the report is wrong about the current code, follow the code and say so in a comment in your final answer.

Acceptance: gofmt-formatted Go, go vet clean for linux and windows, -race clean, no new dependencies, shell scripts keep set -euo pipefail and quoting. At the end, list the files you changed and the tests you added.
PROMPT
exec "$root/.agy/run.sh" "$p" "/tmp/claude-1000/agy-ipv6-step$n.log" "$tier"
