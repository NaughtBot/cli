//go:build integration

// Package shared provides helpers used by every NaughtBot E2E suite.
//
// The harness coordinates the Go test process, an iOS Simulator running
// the NaughtBot app, and an XCUITest runner via a shared directory of text
// files. This file owns the file-based IPC contract.
//
// Contract (see docs/superpowers/specs/2026-04-12-nb-e2e-testing-design.md):
//
//	Go → XCUITest         qr_url.txt / relay_url.txt / login_url.txt /
//	                      blob_url.txt / approval_request.txt
//	XCUITest → Go         approval_complete.txt / approval_error.txt /
//	                      callback_debug.txt / sekey_debug.txt
package shared

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// E2EDataDir returns the coordination directory for the current run. It
// honours the E2E_DATA_DIR environment variable (populated by setup.sh) and
// falls back to /tmp/nb-e2e for ad-hoc invocations.
func E2EDataDir() string {
	if v := os.Getenv("E2E_DATA_DIR"); v != "" {
		return v
	}
	return "/tmp/nb-e2e"
}

// EnsureE2EDataDir creates E2EDataDir() if it does not already exist.
// Returns the resolved path so callers can log where coordination files live.
func EnsureE2EDataDir() (string, error) {
	dir := E2EDataDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir E2EDataDir %q: %w", dir, err)
	}
	return dir, nil
}

// WriteE2EFile writes value to <E2EDataDir>/name atomically. An empty string
// is still written (not treated as a delete); callers that need removal use
// ClearE2EFile.
func WriteE2EFile(name, value string) error {
	dir, err := EnsureE2EDataDir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, name)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(value), 0o644); err != nil {
		return fmt.Errorf("write %q: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename %q → %q: %w", tmp, path, err)
	}
	return nil
}

// ReadE2EFile returns the (trimmed) contents of <E2EDataDir>/name, or ""
// plus an error if the file is missing.
func ReadE2EFile(name string) (string, error) {
	dir := E2EDataDir()
	path := filepath.Join(dir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// ClearE2EFile removes <E2EDataDir>/name if it exists. Missing files are not
// an error — idempotent cleanup is what callers want.
func ClearE2EFile(name string) error {
	dir := E2EDataDir()
	path := filepath.Join(dir, name)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %q: %w", path, err)
	}
	return nil
}

// ClearAllE2EFiles removes every coordination file in E2EDataDir. Useful as
// the first step of a test to guarantee no stale state from a previous run.
func ClearAllE2EFiles() error {
	dir := E2EDataDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Never delete env.sh; setup.sh owns it.
		if name == "env.sh" {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// WaitForE2EFile polls <E2EDataDir>/name until it exists and is non-empty,
// or timeout elapses. Returns the trimmed contents on success.
func WaitForE2EFile(name string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for {
		value, err := ReadE2EFile(name)
		if err == nil && value != "" {
			return value, nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("timed out after %s waiting for %s", timeout, name)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
