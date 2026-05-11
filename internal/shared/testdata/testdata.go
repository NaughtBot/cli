package testdata

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Path returns the canonical shared testdata path under repo-root data/.
func Path(t testing.TB, name string) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve testdata package path")
	}

	path := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../../data", name))
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("shared testdata %q not found at %s: %v", name, path, err)
	}

	return path
}
