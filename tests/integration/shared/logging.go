//go:build integration

package shared

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// LogEnvDump prints every NaughtBot-related environment variable plus the CLI
// path, its size, and the current process PID. Call this at the start of
// every suite so failure logs always contain enough context to reproduce.
func LogEnvDump(t *testing.T) {
	t.Helper()
	t.Logf("[E2E] env dump — pid=%d", os.Getpid())
	keys := []string{
		"E2E_DATA_DIR",
		"NB_CONFIG_DIR",
		"NB_CLI_PATH",
		"NB_CLI",
		"AGE_PLUGIN",
		"SK_DYLIB",
		"PKCS11_DYLIB",
		"SIMULATOR_ID",
		"TEST_LOGIN_URL",
		"TEST_RELAY_URL",
		"TEST_BLOB_URL",
		"TEST_SSH_HOST",
		"TEST_SSH_PORT",
		"NB_APP_PATH",
		"RUN_NB_E2E",
	}
	for _, k := range keys {
		t.Logf("[E2E]   %s=%s", k, os.Getenv(k))
	}
	if cli := os.Getenv("NB_CLI_PATH"); cli != "" {
		if st, err := os.Stat(cli); err == nil {
			t.Logf("[E2E]   CLI size=%d bytes mtime=%s", st.Size(), st.ModTime().Format(time.RFC3339))
		} else {
			t.Logf("[E2E]   CLI stat failed: %v", err)
		}
	}
}

// LogStep writes a single numbered step line to the test log. Using this
// helper (rather than ad-hoc t.Logf) keeps every suite's log format
// consistent with the design's "Step N" requirement.
func LogStep(t *testing.T, n int, format string, args ...any) {
	t.Helper()
	msg := fmt.Sprintf(format, args...)
	t.Logf("[E2E] Step %d — %s", n, msg)
}

// LogE2ELines copies stdout/stderr lines from a captured buffer into the
// test log, prefixing each with a label so interleaved CLI output is
// distinguishable from harness output.
func LogE2ELines(t *testing.T, label string, buf *bytes.Buffer) {
	t.Helper()
	if buf == nil {
		return
	}
	scanLines(buf, func(line string) {
		t.Logf("[E2E][%s] %s", label, line)
	})
}

// LogE2ELinesPreview is like LogE2ELines but truncates after maxBytes so
// success paths do not flood the log; callers still use LogE2ELines to dump
// the full buffer on failure.
func LogE2ELinesPreview(t *testing.T, label string, buf *bytes.Buffer, maxBytes int) {
	t.Helper()
	if buf == nil || buf.Len() == 0 {
		return
	}
	data := buf.Bytes()
	if len(data) > maxBytes {
		data = data[:maxBytes]
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if line == "" {
			continue
		}
		t.Logf("[E2E][%s] %s", label, line)
	}
	if buf.Len() > maxBytes {
		t.Logf("[E2E][%s] ... (truncated %d / %d bytes)", label, maxBytes, buf.Len())
	}
}

// DumpCoordinationDir walks E2EDataDir and logs file names + contents. It is
// intended for failure paths where seeing the XCUITest → Go state is the
// fastest route to the root cause.
func DumpCoordinationDir(t *testing.T) {
	t.Helper()
	dir := E2EDataDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Logf("[E2E] cannot read coordination dir %s: %v", dir, err)
		return
	}
	t.Logf("[E2E] coordination dir %s contents:", dir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		path := dir + "/" + name
		data, err := os.ReadFile(path)
		if err != nil {
			t.Logf("[E2E]   %s — read failed: %v", name, err)
			continue
		}
		text := strings.TrimSpace(string(data))
		if len(text) > 2048 {
			text = text[:2048] + "…(truncated)"
		}
		t.Logf("[E2E]   %s (%d bytes):\n%s", name, len(data), text)
	}
}

// scanLines is a tiny helper that iterates complete lines from a byte
// buffer without touching the original content, so callers can re-read.
func scanLines(buf *bytes.Buffer, fn func(string)) {
	text := buf.String()
	for {
		idx := strings.IndexByte(text, '\n')
		if idx < 0 {
			if text != "" {
				fn(text)
			}
			return
		}
		fn(strings.TrimRight(text[:idx], "\r"))
		text = text[idx+1:]
	}
}

// TeeToLog wraps an io.Writer so that written bytes also land in the test
// log. Used when streaming long-running CLI stdout/stderr through a
// go-test-friendly writer.
func TeeToLog(t *testing.T, label string, w io.Writer) io.Writer {
	t.Helper()
	return &teeWriter{t: t, label: label, inner: w}
}

type teeWriter struct {
	t       *testing.T
	label   string
	inner   io.Writer
	pending bytes.Buffer
}

func (tw *teeWriter) Write(p []byte) (int, error) {
	tw.pending.Write(p)
	for {
		line, err := tw.pending.ReadString('\n')
		if err != nil {
			// Partial line — put it back and wait for more data.
			tw.pending.Reset()
			tw.pending.WriteString(line)
			break
		}
		tw.t.Logf("[E2E][%s] %s", tw.label, strings.TrimRight(line, "\r\n"))
	}
	if tw.inner != nil {
		if _, err := tw.inner.Write(p); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}
