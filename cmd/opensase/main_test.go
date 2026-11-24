package main

import (
	"strings"
	"testing"
)

func TestFormatStatus(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]any
		expected string
	}{
		{
			name: "AllKeysPresent",
			input: map[string]any{
				"state":           "connected",
				"edge":            "edge-us-east",
				"kex":             "X25519MLKEM768",
				"pq":              true,
				"snapshotVersion": float64(42),
				"stale":           false,
			},
			expected: "State: connected  Edge: edge-us-east  PQ: X25519MLKEM768  Policy: v42",
		},
		{
			name: "StalePolicy",
			input: map[string]any{
				"state":           "connected",
				"edge":            "edge-eu-west",
				"kex":             "X25519MLKEM768",
				"snapshotVersion": 5,
				"stale":           true,
			},
			expected: "State: connected  Edge: edge-eu-west  PQ: X25519MLKEM768  Policy: v5 (stale)",
		},
		{
			name: "PQWithoutKex",
			input: map[string]any{
				"state": "connected",
				"pq":    true,
			},
			expected: "State: connected  PQ: true",
		},
		{
			name: "OnlyState",
			input: map[string]any{
				"state": "stopped",
			},
			expected: "State: stopped",
		},
		{
			name: "ErrorState",
			input: map[string]any{
				"state": "error",
				"error": "certificate expired",
			},
			expected: "State: error  Error: certificate expired",
		},
		{
			name:     "EmptyMap",
			input:    map[string]any{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatStatus(tt.input)
			if got != tt.expected {
				t.Errorf("formatStatus() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestFormatFlowsTable(t *testing.T) {
	flows := []map[string]any{
		{
			"start": "2026-11-24T12:00:00Z",
			"decision": map[string]any{
				"action": "allow",
			},
			"flow": map[string]any{
				"protocol": "tcp",
				"domain":   "example.com",
				"app":      "browser",
			},
		},
		{
			"start": "2026-11-24T12:01:00Z",
			"decision": map[string]any{
				"action": "block",
			},
			"flow": map[string]any{
				"protocol": "udp",
				"dstIp":    "192.0.2.1",
				"dstPort":  float64(53),
			},
		},
	}

	out := formatFlowsTable(flows)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines (header + 2 rows), got %d: %q", len(lines), out)
	}

	header := lines[0]
	for _, col := range []string{"TIME", "ACTION", "PROTOCOL", "DESTINATION", "APP"} {
		if !strings.Contains(header, col) {
			t.Errorf("header missing %q: %s", col, header)
		}
	}

	row1 := lines[1]
	if !strings.Contains(row1, "allow") || !strings.Contains(row1, "tcp") || !strings.Contains(row1, "example.com") || !strings.Contains(row1, "browser") {
		t.Errorf("row 1 mismatch: %s", row1)
	}

	row2 := lines[2]
	if !strings.Contains(row2, "block") || !strings.Contains(row2, "udp") || !strings.Contains(row2, "192.0.2.1:53") {
		t.Errorf("row 2 mismatch: %s", row2)
	}
}

func TestArgumentParsing(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantExit int
	}{
		{
			name:     "NoArgs",
			args:     []string{},
			wantExit: 2,
		},
		{
			name:     "HelpFlag",
			args:     []string{"--help"},
			wantExit: 0,
		},
		{
			name:     "VersionCommand",
			args:     []string{"version"},
			wantExit: 0,
		},
		{
			name:     "VersionJson",
			args:     []string{"-json", "version"},
			wantExit: 0,
		},
		{
			name:     "UnknownCommand",
			args:     []string{"nonexistent-cmd"},
			wantExit: 2,
		},
		{
			name:     "UnknownGlobalFlag",
			args:     []string{"-unknown-flag", "status"},
			wantExit: 2,
		},
		{
			name:     "EnrollMissingControl",
			args:     []string{"enroll"},
			wantExit: 2,
		},
		{
			name:     "EnrollMissingKeyFile",
			args:     []string{"enroll", "-control", "https://cp.example.com", "-key-file", "/nonexistent/test/key.txt"},
			wantExit: 1,
		},
		{
			name:     "UnenrollNonTerminalWithoutYes",
			args:     []string{"unenroll"},
			wantExit: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := run(tt.args)
			if code != tt.wantExit {
				t.Errorf("run(%v) = %d, want %d", tt.args, code, tt.wantExit)
			}
		})
	}
}
