package crypto

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestSetupAttestedKeyZKActionBuildsExpectedTargets(t *testing.T) {
	source, err := os.ReadFile("../../.github/actions/setup-attested-key-zk/action.yml")
	if err != nil {
		t.Fatalf("read setup-attested-key-zk action: %v", err)
	}

	contents := string(source)
	if !strings.Contains(contents, "attested-key-zk/AckAgentAttestedKeyZKApple.artifactbundle") {
		t.Fatalf("setup-attested-key-zk action should cache the Apple Swift artifact bundle output")
	}
	if !strings.Contains(contents, "attested-key-zk/AckAgentAttestedKeyZKAndroid.artifactbundle") {
		t.Fatalf("setup-attested-key-zk action should cache the Android Swift artifact bundle output")
	}
	if !strings.Contains(contents, "git submodule update --init --recursive attested-key-zk/third_party/longfellow-zk") {
		t.Fatalf("setup-attested-key-zk action should initialize the longfellow-zk submodule before building")
	}
	if !strings.Contains(contents, "make -C attested-key-zk static-lib") {
		t.Fatalf("setup-attested-key-zk action should build the native static library target")
	}
	if !strings.Contains(contents, "make -C attested-key-zk ensure-apple-artifactbundle") {
		t.Fatalf("setup-attested-key-zk action should build the Apple artifact bundle target")
	}
	if !strings.Contains(contents, "make -C attested-key-zk ensure-android-artifactbundle") {
		t.Fatalf("setup-attested-key-zk action should build the Android artifact bundle target")
	}
}

func TestCIGoWorkflowStagesAttestedKeyZKForOOBSignCLI(t *testing.T) {
	workflow, err := os.ReadFile("../../.github/workflows/ci-go.yml")
	if err != nil {
		t.Fatalf("read ../../.github/workflows/ci-go.yml: %v", err)
	}

	contents := string(workflow)
	if !strings.Contains(contents, "name: attested-key-zk-static-lib") {
		t.Fatalf("ci-go workflow should upload a dedicated attested-key-zk artifact")
	}
	if !strings.Contains(contents, "mkdir -p attested-key-zk/build attested-key-zk/include/attested_key_zk") {
		t.Fatalf("ci-go workflow should prepare the attested-key-zk CGO directories before tests")
	}
	if !strings.Contains(contents, "cp attested-key-zk-dist/lib/libattested_key_zk.a attested-key-zk/build/") {
		t.Fatalf("ci-go workflow should install libattested_key_zk.a into attested-key-zk/build for CGO")
	}
	if !strings.Contains(contents, "cp attested-key-zk-dist/include/attested_key_zk/approval_proof_v1_zk.h attested-key-zk/include/attested_key_zk/") {
		t.Fatalf("ci-go workflow should install the attested-key-zk public header for CGO")
	}
}

func TestOOBSignCLIMakefileBuildsAttestedKeyZKBeforeTests(t *testing.T) {
	source, err := os.ReadFile("../Makefile")
	if err != nil {
		t.Fatalf("read oobsign-cli Makefile: %v", err)
	}

	contents := string(source)
	if !strings.Contains(contents, "ensure-attested-key-zk-static-lib:") {
		t.Fatalf("oobsign-cli Makefile should define a native attested-key-zk prerequisite target")
	}
	if !strings.Contains(contents, "$(MAKE) -C ../attested-key-zk static-lib") {
		t.Fatalf("oobsign-cli Makefile should build the attested-key-zk static library before CGO operations")
	}
	if !strings.Contains(contents, "test: ensure-attested-key-zk-static-lib") {
		t.Fatalf("oobsign-cli test target should depend on the attested-key-zk static library")
	}
}

func TestMobileCIWorkflowsProvisionAttestedKeyZKArtifactBundles(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		targetHint string
	}{
		{
			name:       "iOS workflow",
			path:       "../../.github/workflows/ci-ios.yml",
			targetHint: "target: apple-artifactbundle",
		},
		{
			name:       "Android workflow",
			path:       "../../.github/workflows/ci-android.yml",
			targetHint: "target: android-artifactbundle",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			workflow, err := os.ReadFile(tc.path)
			if err != nil {
				t.Fatalf("read %s: %v", tc.path, err)
			}

			contents := string(workflow)
			if !strings.Contains(contents, "./.github/actions/setup-attested-key-zk") {
				t.Fatalf("%s should provision attested-key-zk before building", tc.name)
			}
			if !strings.Contains(contents, tc.targetHint) {
				t.Fatalf("%s should request %s", tc.name, tc.targetHint)
			}
		})
	}
}

func TestAttestedKeyZKArtifactBundleBuildScriptHasMacOSArchiveFallback(t *testing.T) {
	source, err := os.ReadFile("../../attested-key-zk/build-artifactbundle.sh")
	if err != nil {
		t.Fatalf("read attested-key-zk/build-artifactbundle.sh: %v", err)
	}

	contents := string(source)
	if !strings.Contains(contents, "xcrun --sdk macosx --find libtool") {
		t.Fatalf("build-artifactbundle.sh should fall back to libtool when llvm-ar is unavailable")
	}
	if !strings.Contains(contents, "\"$archive_tool\" -static -o \"$output\" \"$@\"") {
		t.Fatalf("build-artifactbundle.sh should merge Apple archives with libtool when needed")
	}
}

func TestAttestedKeyZKWasmBuildSkipsWasmRecompileByDefault(t *testing.T) {
	type packageManifest struct {
		Scripts map[string]string `json:"scripts"`
	}

	raw, err := os.ReadFile("../../attested-key-zk/bindings/wasm/package.json")
	if err != nil {
		t.Fatalf("read attested-key-zk wasm package.json: %v", err)
	}

	var manifest packageManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("unmarshal attested-key-zk wasm package.json: %v", err)
	}

	if manifest.Scripts["build"] != "pnpm build:ts" {
		t.Fatalf("default wasm package build should only run the TypeScript wrapper; got %q", manifest.Scripts["build"])
	}
	if !strings.Contains(manifest.Scripts["verify"], "pnpm build:wasm") {
		t.Fatalf("verify script should still rebuild the wasm binary explicitly")
	}
}
