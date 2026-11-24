package mobile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func assertPrivate(t *testing.T, path string) {
	t.Helper()
	priv, err := isPrivatePath(path)
	if err != nil {
		t.Fatalf("%s: isPrivatePath error: %v", path, err)
	}
	if !priv {
		t.Fatalf("%s: expected private path", path)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s: stat error: %v", path, err)
		}
		if !st.IsDir() && st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: mode %v, want 0600", path, st.Mode().Perm())
		}
	}
}

func TestIsPrivatePath(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "private.txt")
	if err := os.WriteFile(f, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	// On Windows the mode is ignored: the file is private only after restrictPath.
	if err := restrictPath(f, false); err != nil {
		t.Fatal(err)
	}
	assertPrivate(t, f)
}
