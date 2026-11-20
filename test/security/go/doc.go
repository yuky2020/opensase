// Package securitytest holds the OpenSASE security tests that need code: crafted TLS
// handshakes and certificates, crafted packets inside a real WireGuard tunnel, and HTTP
// input fuzzing. The black-box shell suite lives one directory up (test/security/run.sh).
//
// Two kinds of tests live here:
//
//   - unit checks (TestUnit*) need no running stack and always run (make sectest-unit);
//   - stack checks attack the local dev stack (deploy/dev) and are skipped unless
//     OPENSASE_SECTEST=1 (make sectest).
//
// Every check prints one line "PASS|FAIL|KNOWN-FAIL|SKIP <ID> <description>" and, when
// SECTEST_RESULTS names a file, appends the same line to it. A KNOWN-FAIL is a reproduced
// finding (see docs/security/sectest-*.md) and does not fail the Go test; a FAIL does.
//
// Targets: only loopback and the local docker network. Secrets (admin token, CA keys) are
// read from deploy/dev at runtime and never printed.
package securitytest
