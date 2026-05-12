//go:build integration

// Package pkcs11 — helpers shared by the three PKCS#11 e2e tests.
//
// Everything here is structural: dylib discovery / copy, PKCS#11 library
// initialization, object lookup, P-256 signature / ECDH math, and the
// failure-context dumper. Test bodies stay short and read like step lists.
package pkcs11

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/naughtbot/cli/tests/integration/shared"
)

// P-256 wire-format constants. Centralised so test assertions and helpers
// stay in sync with the provider's internal expectations.
const (
	p256SignatureLen = 64 // r || s (32 bytes each)
	p256DigestLen    = 32 // SHA-256 digest / CKM_ECDSA input size
	p256SharedLen    = 32 // ECDH shared secret size
	p256UncompLen    = 65 // 0x04 || X || Y
)

// repoRoot resolves the monorepo root by walking up from the suite directory.
// Honours REPO_ROOT for callers that run the tests from a non-canonical cwd.
func repoRoot(t *testing.T) string {
	t.Helper()
	if v := os.Getenv("REPO_ROOT"); v != "" {
		return v
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("repoRoot: getwd: %v", err)
	}
	// tests/integration/pkcs11 -> tests/integration -> tests -> repo root
	return filepath.Clean(filepath.Join(cwd, "..", "..", ".."))
}

// ensurePKCS11Dylib makes sure libnb-pkcs11.dylib exists on disk and
// returns its absolute path. Mirrors the ssh suite's ensureSKProviderDylib:
// honour PKCS11_DYLIB first, then the canonical provider path, and fall back
// to `make build DEV=1`.
//
// macOS caches dylibs by absolute path within a process, so callers MUST copy
// the returned path into a per-test tempdir before passing it to the
// miekg/pkcs11 loader. Otherwise a rebuild silently serves the cached image.
func ensurePKCS11Dylib(t *testing.T) string {
	t.Helper()

	if v := os.Getenv("PKCS11_DYLIB"); v != "" {
		if _, err := os.Stat(v); err == nil {
			shared.LogStep(t, 0, "ensurePKCS11Dylib: using PKCS11_DYLIB=%s", v)
			return v
		}
		t.Logf("[E2E] PKCS11_DYLIB=%s not on disk, falling back to canonical path", v)
	}

	root := repoRoot(t)
	canonical := filepath.Join(root, "pkcs11-provider", "libnb-pkcs11.dylib")
	if _, err := os.Stat(canonical); err == nil {
		shared.LogStep(t, 0, "ensurePKCS11Dylib: found canonical %s", canonical)
		return canonical
	}

	shared.LogStep(t, 0, "ensurePKCS11Dylib: dylib missing, building via `make build DEV=1`")
	cmd := exec.Command("make", "-C", root, "build", "DEV=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ensurePKCS11Dylib: build failed: %v\n%s", err, string(out))
	}
	if _, err := os.Stat(canonical); err != nil {
		t.Fatalf("ensurePKCS11Dylib: build succeeded but %s still missing: %v\n%s", canonical, err, string(out))
	}
	return canonical
}

// copyDylibToTempdir copies src to <tempdir>/libnb-pkcs11.dylib. Same
// rationale as the ssh suite: avoid macOS's per-path dylib cache across
// rebuilds within a single process.
func copyDylibToTempdir(t *testing.T, src, dstDir string) string {
	t.Helper()
	dst := filepath.Join(dstDir, "libnb-pkcs11.dylib")
	in, err := os.Open(src)
	if err != nil {
		t.Fatalf("copyDylibToTempdir: open %s: %v", src, err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatalf("copyDylibToTempdir: create %s: %v", dst, err)
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		t.Fatalf("copyDylibToTempdir: copy: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("copyDylibToTempdir: close: %v", err)
	}
	shared.LogStep(t, 0, "copyDylibToTempdir: %s -> %s", src, dst)
	return dst
}

// initializePKCS11 loads the dylib via miekg/pkcs11 and calls C_Initialize.
// Caller is responsible for pairing with p.Destroy() via t.Cleanup or defer.
func initializePKCS11(t *testing.T, libPath string) *pkcs11.Ctx {
	t.Helper()
	p := pkcs11.New(libPath)
	if p == nil {
		t.Fatalf("initializePKCS11: failed to load dylib: %s", libPath)
	}
	if err := p.Initialize(); err != nil {
		t.Fatalf("initializePKCS11: C_Initialize: %v", err)
	}
	return p
}

// openFirstSession opens a RW session on the first populated slot. Our
// provider exposes a single virtual slot so this is equivalent to
// "open the only session that exists".
func openFirstSession(t *testing.T, p *pkcs11.Ctx) pkcs11.SessionHandle {
	t.Helper()
	slots, err := p.GetSlotList(true)
	if err != nil {
		t.Fatalf("openFirstSession: C_GetSlotList: %v", err)
	}
	if len(slots) == 0 {
		t.Fatalf("openFirstSession: no slots available")
	}
	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		t.Fatalf("openFirstSession: C_OpenSession: %v", err)
	}
	return session
}

// findPrivateKeyByCKAID finds a PKCS#11 private-key object whose CKA_ID
// matches the device auth pubkey hex. The provider stores CKA_ID as the raw
// bytes of the lowercase hex string (“[]byte("af74…")“), NOT the decoded
// key bytes — callers pass the hex string directly.
func findPrivateKeyByCKAID(
	t *testing.T,
	p *pkcs11.Ctx,
	session pkcs11.SessionHandle,
	ckaIDHex string,
) pkcs11.ObjectHandle {
	t.Helper()
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(ckaIDHex)),
	}
	if err := p.FindObjectsInit(session, template); err != nil {
		t.Fatalf("findPrivateKeyByCKAID: C_FindObjectsInit: %v", err)
	}
	defer p.FindObjectsFinal(session)
	objects, _, err := p.FindObjects(session, 1)
	if err != nil {
		t.Fatalf("findPrivateKeyByCKAID: C_FindObjects: %v", err)
	}
	if len(objects) == 0 {
		t.Fatalf("findPrivateKeyByCKAID: no key found with CKA_ID=%s", ckaIDHex)
	}
	return objects[0]
}

// getPublicKeyFromObject retrieves CKA_EC_POINT and parses it into an ecdsa
// public key we can use for signature verification.
func getPublicKeyFromObject(
	t *testing.T,
	p *pkcs11.Ctx,
	session pkcs11.SessionHandle,
	keyHandle pkcs11.ObjectHandle,
) *ecdsa.PublicKey {
	t.Helper()
	attrs, err := p.GetAttributeValue(session, keyHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		t.Fatalf("getPublicKeyFromObject: C_GetAttributeValue(CKA_EC_POINT): %v", err)
	}
	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
		t.Fatalf("getPublicKeyFromObject: CKA_EC_POINT missing or empty")
	}
	pub, err := parseECPointToPublicKey(attrs[0].Value)
	if err != nil {
		t.Fatalf("getPublicKeyFromObject: parseECPointToPublicKey: %v", err)
	}
	return pub
}

// parseECPointToPublicKey parses CKA_EC_POINT (DER OCTET STRING wrapping an
// uncompressed SEC1 point, i.e. `04 41 04 X Y`, 67 bytes) into an
// ecdsa.PublicKey on P-256.
func parseECPointToPublicKey(ecPoint []byte) (*ecdsa.PublicKey, error) {
	if len(ecPoint) < 67 {
		return nil, fmt.Errorf("EC point too short: expected >=67, got %d", len(ecPoint))
	}
	if ecPoint[0] != 0x04 || ecPoint[1] != 0x41 {
		return nil, fmt.Errorf("invalid OCTET STRING header: expected 04 41, got %02x %02x", ecPoint[0], ecPoint[1])
	}
	point := ecPoint[2:]
	if len(point) != p256UncompLen {
		return nil, fmt.Errorf("uncompressed point: expected %d bytes, got %d", p256UncompLen, len(point))
	}
	if point[0] != 0x04 {
		return nil, fmt.Errorf("not an uncompressed point: expected 0x04 prefix, got 0x%02x", point[0])
	}
	x := new(big.Int).SetBytes(point[1:33])
	y := new(big.Int).SetBytes(point[33:65])
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// verifyP256RawSignature verifies a 64-byte raw `r || s` ECDSA signature
// against an already-computed 32-byte digest.
func verifyP256RawSignature(pub *ecdsa.PublicKey, digest, rawSig []byte) bool {
	if len(rawSig) != p256SignatureLen || len(digest) != p256DigestLen {
		return false
	}
	r := new(big.Int).SetBytes(rawSig[:32])
	s := new(big.Int).SetBytes(rawSig[32:])
	return ecdsa.Verify(pub, digest, r, s)
}

// generateTestKeyPair creates an ephemeral P-256 keypair for ECDH testing.
func generateTestKeyPair(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generateTestKeyPair: %v", err)
	}
	return k
}

// encodeUncompressedPoint encodes a P-256 public key as a 65-byte
// uncompressed SEC1 point (0x04 || X || Y). This is the format
// miekg/pkcs11's NewECDH1DeriveParams expects.
func encodeUncompressedPoint(pub *ecdsa.PublicKey) []byte {
	point := make([]byte, p256UncompLen)
	point[0] = 0x04
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	copy(point[1+32-len(xBytes):33], xBytes)
	copy(point[33+32-len(yBytes):65], yBytes)
	return point
}

// cliEnv is the env every CLI subprocess inherits — identical in shape to
// login / ssh so that a relogin / keys --sync run from inside the suite
// sees the same acceptance flags.
func cliEnv(env *shared.TestEnv) []string {
	e := os.Environ()
	e = append(e,
		"NB_CONFIG_DIR="+env.ConfigDir,
		"TEST_LOGIN_URL="+env.LoginURL,
		"TEST_RELAY_URL="+env.RelayURL,
		"TEST_BLOB_URL="+env.BlobURL,
		"SKIP_VERIFY_ATTESTATION=true",
		"NB_ACCEPT_SOFTWARE_APPROVER_KEYS=1",
	)
	return e
}

// getDeviceAuthPublicKeyHex reads the CLI profile JSON and returns the
// lowercase hex-encoded compressed-SEC1 auth public key of the first
// device. The PKCS#11 provider uses this value as the CKA_ID of the
// device-auth-key object, so tests look keys up by the same hex string.
//
// Mirrors the archived suite's helper of the same name — reading the
// profile directly is more robust than parsing CLI stdout, and does not
// require the CLI to be re-invoked on every test.
func getDeviceAuthPublicKeyHex(env *shared.TestEnv) (string, error) {
	configDir := env.ConfigDir
	if configDir == "" {
		return "", fmt.Errorf("getDeviceAuthPublicKeyHex: NB_CONFIG_DIR not set on TestEnv")
	}
	profile := env.ProfileName
	if profile == "" {
		profile = "default"
	}
	profilePath := filepath.Join(configDir, "profiles", profile+".json")
	data, err := os.ReadFile(profilePath)
	if err != nil {
		return "", fmt.Errorf("read profile %s: %w", profilePath, err)
	}

	var decoded struct {
		UserAccount struct {
			Devices []struct {
				AuthPublicKeyHex string `json:"authPublicKeyHex"`
				AuthPublicKey    string `json:"authPublicKey"`
			} `json:"devices"`
		} `json:"user_account"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return "", fmt.Errorf("parse profile %s: %w", profilePath, err)
	}

	for _, dev := range decoded.UserAccount.Devices {
		hexKey := strings.TrimSpace(dev.AuthPublicKeyHex)
		if hexKey == "" {
			raw := strings.TrimSpace(dev.AuthPublicKey)
			if raw == "" {
				continue
			}
			if decoded, decErr := base64.StdEncoding.DecodeString(raw); decErr == nil {
				hexKey = hex.EncodeToString(decoded)
			} else if decoded, decErr := hex.DecodeString(raw); decErr == nil {
				hexKey = hex.EncodeToString(decoded)
			} else {
				hexKey = raw
			}
		}
		if hexKey != "" {
			return strings.ToLower(hexKey), nil
		}
	}
	return "", fmt.Errorf("no device auth public key found in profile %s", profilePath)
}

// lockedBuffer mirrors ssh/helpers.go: a mutex-guarded bytes.Buffer safe for
// concurrent writes from multiple goroutines, with Snapshot() for
// race-free dump paths. Retained here so the failure dumper has a buffer
// to print even for PKCS#11 tests that do not shell out to the CLI.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *lockedBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

func (b *lockedBuffer) Snapshot() *bytes.Buffer {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := bytes.NewBuffer(make([]byte, 0, b.buf.Len()))
	out.Write(b.buf.Bytes())
	return out
}

// removeIfExists is the same cleanup convenience shape as the ssh suite.
func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// dumpFailureContext mirrors the ssh suite's failure dumper — env summary,
// coordination dir, CLI/test buffer, and the last 200 lines of the device
// log. Kept API-compatible so tests call it the same way.
func dumpFailureContext(t *testing.T, env *shared.TestEnv, cliBuf *lockedBuffer) {
	t.Helper()
	t.Log("[E2E] ─── failure context ────────────────────────────────────")
	if env != nil {
		t.Logf("[E2E] env: cli=%s config=%s sim=%s data=%s",
			env.CLIPath, env.ConfigDir, env.SimulatorID, env.DataDir)
	}
	shared.DumpCoordinationDir(t)
	if cliBuf != nil && cliBuf.Len() > 0 {
		snap := cliBuf.Snapshot()
		t.Logf("[E2E] CLI buffer (%d bytes):", snap.Len())
		shared.LogE2ELines(t, "nb", snap)
	}
	logPath := os.Getenv("SIM_LOG_FILE")
	if logPath == "" {
		logPath = "/tmp/nb-pkcs11-sim-log"
	}
	if data, err := os.ReadFile(logPath); err == nil {
		lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		start := len(lines) - 200
		if start < 0 {
			start = 0
		}
		t.Logf("[E2E] device log %s (last %d lines):", logPath, len(lines)-start)
		for _, line := range lines[start:] {
			t.Logf("[E2E][sim] %s", line)
		}
	} else {
		t.Logf("[E2E] device log %s unavailable: %v", logPath, err)
	}
	t.Log("[E2E] ─── end failure context ────────────────────────────────")
}
