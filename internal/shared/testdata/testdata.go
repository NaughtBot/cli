package testdata

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Path returns the canonical shared testdata path under the cli repo-root
// testdata/ directory.
func Path(t testing.TB, name string) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve testdata package path")
	}

	// testdata.go lives at internal/shared/testdata/testdata.go, so the repo
	// root is three levels up and the fixtures live under repo-root testdata/.
	path := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../testdata", name))
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("shared testdata %q not found at %s: %v", name, path, err)
	}

	return path
}
