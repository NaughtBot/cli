// age-plugin-nb is an age plugin that uses iOS-stored X25519 keys.
//
// Installation:
//
//	go build -o age-plugin-nb ./cmd/age-plugin-nb
//	mv age-plugin-nb ~/.local/bin/  # or anywhere in PATH
//
// The binary must be named "age-plugin-nb" and be in the PATH.
//
// Usage:
//
//	# Generate a key (on iOS)
//	nb age keygen
//
//	# Get recipient for encryption
//	nb age recipient
//	# -> age1nb1...
//
//	# Encrypt a file (anyone can do this)
//	age -r age1nb1... -o secret.age secret.txt
//
//	# Decrypt (requires iOS approval)
//	age -d -i ~/.config/nb/age-identity.txt secret.age > secret.txt
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/plugin"
	nbage "github.com/naughtbot/cli/internal/age"
)

// debugEnabled reports whether NB_DEBUG is set to a non-empty value.
func debugEnabled() bool {
	return os.Getenv("NB_DEBUG") != ""
}

// debugLogDir returns a user-private directory for debug logs.
func debugLogDir() string {
	if stateHome := strings.TrimSpace(os.Getenv("XDG_STATE_HOME")); stateHome != "" {
		return filepath.Join(stateHome, "nb")
	}

	if cacheDir, err := os.UserCacheDir(); err == nil && cacheDir != "" {
		return filepath.Join(cacheDir, "nb")
	}

	if homeDir, err := os.UserHomeDir(); err == nil && homeDir != "" {
		return filepath.Join(homeDir, ".cache", "nb")
	}

	return filepath.Join(".", ".nb")
}

// debugLogPath returns the debug log file path inside a user-private directory.
func debugLogPath() string {
	return filepath.Join(debugLogDir(), "age-plugin-nb.log")
}

func openDebugLogFile() (*os.File, error) {
	logDir := debugLogDir()
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return nil, err
	}

	path := debugLogPath()
	if err := validateDebugLogPath(path); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}

	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("debug log path %q is not a regular file", path)
	}

	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func validateDebugLogPath(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("debug log path %q must not be a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("debug log path %q is not a regular file", path)
	}
	return nil
}

func appendDebugLogEntry(msg string) (err error) {
	f, err := openDebugLogFile()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := f.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()

	_, err = f.WriteString(msg + "\n")
	return err
}

// debugLog writes to stderr and a debug file when NB_DEBUG is set.
// The log file is kept under a user-private directory to avoid shared /tmp exposure.
func debugLog(format string, args ...interface{}) {
	if !debugEnabled() {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, msg)
	if err := appendDebugLogEntry(msg); err != nil {
		fmt.Fprintf(os.Stderr, "[age-plugin-nb] debug log write failed: %v\n", err)
	}
}

func main() {
	debugLog("[age-plugin-nb] STARTUP: argc=%d", len(os.Args))

	// Create the plugin
	p, err := plugin.New("nb")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create plugin: %v\n", err)
		os.Exit(1)
	}

	// Register recipient handler - called when encrypting to age1nb1...
	// The data parameter contains the 32-byte public key
	p.HandleRecipient(func(data []byte) (age.Recipient, error) {
		if len(data) != 32 {
			return nil, fmt.Errorf("invalid recipient data length: %d", len(data))
		}
		return &nbage.Recipient{PublicKey: data}, nil
	})

	// Register identity handler - called when decrypting with AGE-PLUGIN-NB-...
	// The data parameter contains the key fingerprint as bytes
	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		fingerprint := string(data)

		// Debug: log to stderr for visibility in tests
		debugLog("[age-plugin-nb] identity handler called, fingerprint=%q", fingerprint)
		debugLog("[age-plugin-nb] NB_CONFIG_DIR env=%q", os.Getenv("NB_CONFIG_DIR"))
		debugLog("[age-plugin-nb] ConfigDir()=%s", nbage.ConfigDir())
		debugLog("[age-plugin-nb] ConfigPath()=%s", nbage.ConfigPath())
		debugLog("[age-plugin-nb] ProfilesDir()=%s", nbage.ProfilesDir())

		// Load config to find the key
		cfg, err := nbage.LoadConfig()
		if err != nil {
			debugLog("[age-plugin-nb] failed to load config: %v", err)
			return nil, fmt.Errorf("failed to load config: %v", err)
		}

		debugLog("[age-plugin-nb] config loaded, relay=%s, activeProfile=%s", cfg.RelayURL(), cfg.EffectiveProfile())

		if !cfg.IsLoggedIn() {
			debugLog("[age-plugin-nb] not logged in")
			return nil, fmt.Errorf("not logged in: run 'nb login' first")
		}

		debugLog("[age-plugin-nb] user is logged in")

		// Debug: list all keys in config
		allKeys := cfg.Keys()
		debugLog("[age-plugin-nb] config has %d keys", len(allKeys))
		for i, k := range allKeys {
			debugLog("[age-plugin-nb]   key[%d]: purpose=%s pubKeyHex=%s label=%s", i, k.Purpose, k.Hex(), k.Label)
		}

		// Find the age key - either by fingerprint or by purpose
		var key *nbage.KeyMetadata
		if fingerprint != "" {
			key, _ = cfg.FindKey(fingerprint)
			if key != nil {
				debugLog("[age-plugin-nb] found key by fingerprint: %s", fingerprint)
			}
		}
		if key == nil {
			key = cfg.FindKeyByPurpose(nbage.KeyPurposeAge)
			if key != nil {
				debugLog("[age-plugin-nb] found key by purpose=age")
			}
		}
		if key == nil {
			debugLog("[age-plugin-nb] no age key enrolled (searched fp=%q and purpose=age)", fingerprint)
			return nil, fmt.Errorf("no age key enrolled")
		}

		debugLog("[age-plugin-nb] found key: %s", key.Hex())

		// Create identity with unwrap function
		unwrapFunc := nbage.MakeUnwrapFunc(cfg, key, "encrypted file", 0)
		identity := nbage.IdentityFromKey(key, cfg, unwrapFunc)

		debugLog("[age-plugin-nb] identity created, ready to unwrap")

		return identity, nil
	})

	// Register flags and run
	p.RegisterFlags(flag.CommandLine)
	flag.Parse()
	os.Exit(p.Main())
}
