package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDebugEnabled_Off(t *testing.T) {
	t.Setenv("OOBSIGN_DEBUG", "")
	assert.False(t, debugEnabled())
}

func TestDebugEnabled_On(t *testing.T) {
	t.Setenv("OOBSIGN_DEBUG", "1")
	assert.True(t, debugEnabled())
}

func TestDebugLogPath_UsesXDGStateHome(t *testing.T) {
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)

	path := debugLogPath()
	assert.Equal(t, filepath.Join(stateHome, "oobsign", "age-plugin-oobsign.log"), path)
}

func TestDebugLog_NoFileWhenDisabled(t *testing.T) {
	t.Setenv("OOBSIGN_DEBUG", "")
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	// Use a unique path to verify no file is created
	logPath := debugLogPath()
	os.Remove(logPath) // clean up if exists

	debugLog("should not appear: %s", "test")

	_, err := os.Stat(logPath)
	assert.True(t, os.IsNotExist(err), "log file should not be created when OOBSIGN_DEBUG is unset")
}

func TestDebugLog_WritesWhenEnabled(t *testing.T) {
	t.Setenv("OOBSIGN_DEBUG", "1")
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	logPath := debugLogPath()
	os.Remove(logPath) // clean start
	defer os.Remove(logPath)

	debugLog("test message: %s", "hello")

	data, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.Equal(t, "test message: hello\n", string(data))
}

func TestDebugLog_FilePermissions(t *testing.T) {
	t.Setenv("OOBSIGN_DEBUG", "1")
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	logPath := debugLogPath()
	os.Remove(logPath) // clean start
	defer os.Remove(logPath)

	debugLog("permissions test")

	info, err := os.Stat(logPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(),
		"log file should have 0600 permissions")
}

func TestOpenDebugLogFile_RejectsSymlink(t *testing.T) {
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)

	target := filepath.Join(stateHome, "target.log")
	require.NoError(t, os.WriteFile(target, []byte("existing"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Dir(debugLogPath()), 0o700))
	require.NoError(t, os.Symlink(target, debugLogPath()))

	_, err := openDebugLogFile()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not be a symlink")
}
