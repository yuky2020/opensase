//go:build windows

package mobile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsACL(t *testing.T) {
	dir := t.TempDir()
	defaultFile := filepath.Join(dir, "default.txt")
	if err := os.WriteFile(defaultFile, []byte("hello"), 0o666); err != nil {
		t.Fatal(err)
	}

	priv, err := isPrivatePath(defaultFile)
	if err != nil {
		t.Fatalf("isPrivatePath on default file: %v", err)
	}
	if priv {
		t.Fatal("file created with default inheritance in a fresh temp dir should not be private")
	}

	restrictedFile := filepath.Join(dir, "restricted.txt")
	if err := os.WriteFile(restrictedFile, []byte("secret"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := restrictPath(restrictedFile, false); err != nil {
		t.Fatalf("restrictPath: %v", err)
	}

	priv, err = isPrivatePath(restrictedFile)
	if err != nil {
		t.Fatalf("isPrivatePath on restricted file: %v", err)
	}
	if !priv {
		t.Fatal("restrictPath on a temp file should make isPrivatePath true")
	}
}
