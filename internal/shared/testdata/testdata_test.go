package testdata

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPathUsesCanonicalSharedDataDir(t *testing.T) {
	path := Path(t, "crypto_test_vectors.json")

	if filepath.Base(path) != "crypto_test_vectors.json" {
		t.Fatalf("unexpected basename for shared testdata path: %s", path)
	}
}

func TestOOBSignCLIDataDoesNotShadowSharedVectorFixtures(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve testdata package path")
	}

	cliDataDir := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../data"))
	for _, name := range []string{"crypto_test_vectors.json", "protocol_test_vectors.json"} {
		path := filepath.Join(cliDataDir, name)
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("%s should not exist under oobsign-cli/data; tests should read repo-root data directly", path)
		}
	}
}
