#!/bin/sh
# Write a small UT1-shaped category archive to deploy/dev/data/categories.tar.gz, for CI and
# offline runs of deploy/dev/e2e.sh and make sectest (issue #28). It holds only the names the
# suites test, so no third-party download is needed. Start the stack with CATEGORIES_URL=
# (empty) so the Control Plane keeps this file instead of fetching the real list.
set -eu
cd "$(dirname "$0")/.."
out="deploy/dev/data/categories.tar.gz"
[ -e "$out" ] && [ "${1:-}" != -f ] && { echo "ci-categories-fixture: $out exists (use -f to replace)" >&2; exit 1; }
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/blacklists/gambling" "$tmp/blacklists/adult" "$tmp/blacklists/phishing"
# gambling: a domain (DNS/SNI checks) and a URL entry whose domain is not listed (SEC-DP-128).
printf '%s\n' 0-casino.info casino-fixture.example.net >"$tmp/blacklists/gambling/domains"
printf '%s\n' pages-fixture.example.net/casino >"$tmp/blacklists/gambling/urls"
printf '%s\n' adult-fixture.example.net >"$tmp/blacklists/adult/domains"
printf '%s\n' phishing-fixture.example.net >"$tmp/blacklists/phishing/domains"
mkdir -p "$(dirname "$out")"
tar -C "$tmp" -czf "$out" blacklists
echo "ci-categories-fixture: wrote $out"
