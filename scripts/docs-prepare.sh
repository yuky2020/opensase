#!/bin/sh
# Copy the documents that live outside docs/ into it for the MkDocs site (mkdocs.yml). The
# copies are gitignored; the originals stay the source of truth.
set -eu
cd "$(dirname "$0")/.."

# strip_fm FILE: print FILE without a leading YAML front matter block.
strip_fm() { awk 'NR==1 && /^---$/ {fm=1; next} fm && /^---$/ {fm=0; next} !fm' "$1"; }

strip_fm CONTEXT.md >docs/glossary.md
strip_fm CONTRIBUTING.md >docs/contributing.md
strip_fm CODE_OF_CONDUCT.md >docs/code-of-conduct.md
strip_fm SECURITY.md >docs/security-policy.md
strip_fm test/security/README.md >docs/security/test-suite.md
{
  printf '# Security tester agent\n\n'
  printf '!!! info "Source"\n'
  printf '    The agent definition behind the security suite, from `.claude/agents/security-tester.md`.\n'
  printf '    The tests it maintains are in `test/security/` (see the [test suite](test-suite.md)).\n\n'
  strip_fm .claude/agents/security-tester.md
} >docs/security/security-tester-agent.md
