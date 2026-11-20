package securitytest

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
)

// errSkip marks a check that could not run (missing precondition), as opposed to one that
// ran and found the attack refused (PASS) or accepted (FAIL).
var errSkip = errors.New("skip")

func skipf(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errSkip, fmt.Sprintf(format, a...))
}

var resultsMu sync.Mutex

// record prints one result line and appends it to $SECTEST_RESULTS.
func record(status, id, desc, detail string) {
	line := fmt.Sprintf("%s %s %s", status, id, desc)
	if detail != "" {
		line += " -- " + strings.ReplaceAll(detail, "\n", " ")
	}
	resultsMu.Lock()
	defer resultsMu.Unlock()
	fmt.Println(line)
	if p := os.Getenv("SECTEST_RESULTS"); p != "" {
		f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // G304: operator-chosen results file
		if err == nil {
			_, _ = fmt.Fprintln(f, line)
			_ = f.Close()
		}
	}
}

// check runs one security check as a subtest. fn returns nil when the attack was refused,
// an error describing what got through otherwise, or skipf(...) when it cannot run.
// known is the finding ID ("ST-03") of a reproduced, reported bug: its failure is printed
// as KNOWN-FAIL and does not fail the test run. If a known finding no longer reproduces,
// the check prints PASS with a note so that the report can be updated.
func check(t *testing.T, id, desc, known string, fn func(t *testing.T) error) {
	t.Helper()
	t.Run(id, func(t *testing.T) {
		err := fn(t)
		switch {
		case err == nil && known != "":
			record("PASS", id, desc, "known finding "+known+" no longer reproduces: update the report")
		case err == nil:
			record("PASS", id, desc, "")
		case errors.Is(err, errSkip):
			record("SKIP", id, desc, err.Error())
			t.Skip(err.Error())
		case known != "":
			record("KNOWN-FAIL", id, desc, "["+known+"] "+err.Error())
			t.Log("KNOWN-FAIL [" + known + "]: " + err.Error())
		default:
			record("FAIL", id, desc, err.Error())
			t.Error(err)
		}
	})
}
