package testdata

import (
	"path/filepath"
	"testing"
)

func TestPathUsesCanonicalSharedTestdataDir(t *testing.T) {
	path := Path(t, "crypto_test_vectors.json")

	if filepath.Base(path) != "crypto_test_vectors.json" {
		t.Fatalf("unexpected basename for shared testdata path: %s", path)
	}

	if parent := filepath.Base(filepath.Dir(path)); parent != "testdata" {
		t.Fatalf("expected fixtures under repo-root testdata/, got parent %q (full path %s)", parent, path)
	}
}
