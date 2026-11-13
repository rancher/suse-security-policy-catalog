package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The checksums and the commit that testdata/release records. The release is
// ControllerContainerBlockSysctls/v1.0.6 of rancher/suse-security-policies.
const (
	fixtureWasmSum         = "c383805a6bf87cc8872c86695dc4c7f950482565e4f651acebe65bf50d59a84d"
	fixtureUpstreamSBOMSum = "e949d97f7971dc46c087a5571e5ec428f39557a97a4b1efd79abd909716e5d75"
	fixtureCommit          = "5bbbfd0b8859359a9dcd01fc53d8d5c3114e6c7d"
	fixturePolicyPath      = "/kubewarden/policies/" + fixtureCommit + "/policies/ControllerContainerBlockSysctls/"
)

type edit struct{ file, old, new string }

// newRelease copies testdata/release with the edits, and adds a module. The
// real module is too large for the repository, so the copy of the SUSE SBOM
// records the checksums of a small stand-in and of the edited upstream SBOM.
func newRelease(t *testing.T, edits ...edit) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{}
	for _, name := range []string{sbomName, upstreamSBOMName, metadataName} {
		data, err := os.ReadFile(filepath.Join("testdata", "release", name))
		require.NoError(t, err)
		files[name] = string(data)
	}
	for _, e := range edits {
		require.Contains(t, files[e.file], e.old, "the edit does not match %s", e.file)
		files[e.file] = strings.Replace(files[e.file], e.old, e.new, 1)
	}
	wasm := []byte("stand-in for the policy module")
	files[sbomName] = strings.Replace(files[sbomName], fixtureWasmSum, sha256Hex(wasm), 1)
	files[sbomName] = strings.Replace(files[sbomName], fixtureUpstreamSBOMSum, sha256Hex([]byte(files[upstreamSBOMName])), 1)
	files[wasmName] = string(wasm)
	for name, data := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600))
	}
	return dir
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func testOptions(t *testing.T, releaseDir string) options {
	t.Helper()
	return options{
		releaseDir:         releaseDir,
		tag:                "ControllerContainerBlockSysctls/v1.0.6",
		policyName:         "ControllerContainerBlockSysctls",
		releaseVersion:     "1.0.6",
		ociTag:             "v1.0.6",
		ociBase:            "ghcr.io/rancher/suse-security-policies",
		upstreamRepository: "kubewarden/policies",
		output:             filepath.Join(t.TempDir(), "ControllerContainerBlockSysctls"),
	}
}

// newUpstream serves the files by path, relative to the policy directory at
// the fixture commit. "../LICENSE" is the license at the repository root. A
// path that is not in files gets 404, or the status in status.
func newUpstream(t *testing.T, files map[string]string, status map[string]int) (string, *[]string) {
	t.Helper()
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Path)
		rel := strings.TrimPrefix(r.URL.Path, fixturePolicyPath)
		if r.URL.Path == "/kubewarden/policies/"+fixtureCommit+"/LICENSE" {
			rel = "../LICENSE"
		}
		if code, ok := status[rel]; ok {
			w.WriteHeader(code)
			return
		}
		data, ok := files[rel]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(data))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &requests
}

func defaultUpstreamFiles() map[string]string {
	return map[string]string{"README.md": "# Container Block Sysctls\n", "../LICENSE": "Apache License\n"}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(data)
}

func TestRun(t *testing.T) {
	o := testOptions(t, newRelease(t))
	rawURL, _ := newUpstream(t, defaultUpstreamFiles(), nil)
	var out bytes.Buffer
	require.NoError(t, run(o, rawURL, &out))

	assert.Equal(t, readFile(t, "testdata/chart/Chart.yaml"), readFile(t, filepath.Join(o.output, chartFile)))
	assert.Equal(t, readFile(t, "testdata/chart/values.yaml"), readFile(t, filepath.Join(o.output, valuesFile)))
	assert.Equal(t, "# Container Block Sysctls\n", readFile(t, filepath.Join(o.output, readmeFile)))
	assert.Equal(t, "Apache License\n", readFile(t, filepath.Join(o.output, licenseFile)))
	assert.NoFileExists(t, filepath.Join(o.output, questionsFile))
	assert.Contains(t, out.String(), "from the upstream commit "+fixtureCommit)
}

func TestRunWithQuestions(t *testing.T) {
	o := testOptions(t, newRelease(t))
	files := defaultUpstreamFiles()
	files["questions-ui.yml"] = "questions:\n- variable: exclude_namespaces\n"
	rawURL, _ := newUpstream(t, files, nil)
	require.NoError(t, run(o, rawURL, &bytes.Buffer{}))
	assert.Equal(t, files["questions-ui.yml"], readFile(t, filepath.Join(o.output, questionsFile)))
}

func TestRunRemovesOldQuestions(t *testing.T) {
	o := testOptions(t, newRelease(t))
	require.NoError(t, os.MkdirAll(o.output, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(o.output, chartFile), []byte("name: container-block-sysctl\nversion: 1.0.5\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(o.output, questionsFile), []byte("questions: []\n"), 0o600))
	rawURL, _ := newUpstream(t, defaultUpstreamFiles(), nil)
	require.NoError(t, run(o, rawURL, &bytes.Buffer{}))
	assert.NoFileExists(t, filepath.Join(o.output, questionsFile))
	assert.Contains(t, readFile(t, filepath.Join(o.output, chartFile)), "version: 1.0.6\n")
}

func TestRunRevision(t *testing.T) {
	dir := newRelease(t,
		edit{sbomName, `"versionInfo": "1.0.6"`, `"versionInfo": "1.0.6+suse.1"`},
		edit{sbomName, "&tag=v1.0.6", "&tag=v1.0.6_suse.1"},
	)
	o := testOptions(t, dir)
	o.tag, o.releaseVersion, o.ociTag = "ControllerContainerBlockSysctls/v1.0.6+suse.1", "1.0.6+suse.1", "v1.0.6_suse.1"
	rawURL, _ := newUpstream(t, defaultUpstreamFiles(), nil)
	require.NoError(t, run(o, rawURL, &bytes.Buffer{}))
	chart := readFile(t, filepath.Join(o.output, chartFile))
	assert.Contains(t, chart, "\nversion: 1.0.6+suse.1\n")
	assert.Contains(t, chart, "\nappVersion: 1.0.6+suse.1\n")
	assert.Contains(t, chart, "- ghcr.io/rancher/suse-security-policies/container-block-sysctl:v1.0.6_suse.1\n")
	assert.Contains(t, readFile(t, filepath.Join(o.output, valuesFile)), "  tag: v1.0.6_suse.1\n")
}

func TestRunSkipsCurrentChart(t *testing.T) {
	for _, current := range []string{"1.0.6", "1.0.7", "1.0.6+suse.1"} {
		t.Run(current, func(t *testing.T) {
			// The release directory does not exist, so the test also shows
			// that the check comes before any other step.
			o := testOptions(t, filepath.Join(t.TempDir(), "missing"))
			require.NoError(t, os.MkdirAll(o.output, 0o750))
			chart := "name: container-block-sysctl\nversion: " + current + "\n"
			require.NoError(t, os.WriteFile(filepath.Join(o.output, chartFile), []byte(chart), 0o600))
			rawURL, requests := newUpstream(t, defaultUpstreamFiles(), nil)
			var out bytes.Buffer
			require.NoError(t, run(o, rawURL, &out))
			assert.Contains(t, out.String(), "::notice::")
			assert.Empty(t, *requests)
			assert.Equal(t, chart, readFile(t, filepath.Join(o.output, chartFile)))
		})
	}
}

func TestRunRejects(t *testing.T) {
	tests := []struct {
		name    string
		edits   []edit
		change  func(o *options, releaseDir string)
		status  map[string]int
		files   map[string]string
		wantErr string
	}{
		{name: "tag that does not match", change: func(o *options, _ string) { o.tag = "ControllerContainerBlockSysctls/v1.0.7" },
			wantErr: `the tag is "ControllerContainerBlockSysctls/v1.0.7", but the policy name and the release version give "ControllerContainerBlockSysctls/v1.0.6"`},
		{name: "changed module", change: func(_ *options, dir string) {
			require.NoError(t, os.WriteFile(filepath.Join(dir, wasmName), []byte("another module"), 0o600))
		}, wantErr: "policy-sbom.spdx.json does not record the SHA256 checksum " + sha256Hex([]byte("another module")) + " of suse-policy.wasm"},
		{name: "other release version", change: func(o *options, _ string) {
			o.tag, o.releaseVersion = "ControllerContainerBlockSysctls/v1.0.7", "1.0.7"
		}, wantErr: `policy-sbom.spdx.json records the version "1.0.6", but the release version is "1.0.7"`},
		{name: "other OCI tag", change: func(o *options, _ string) { o.ociTag = "v1.0.7" },
			wantErr: `policy-sbom.spdx.json records the OCI tag "v1.0.6", but the request has "v1.0.7"`},
		{name: "other OCI base", change: func(o *options, _ string) { o.ociBase = "ghcr.io/kubewarden/policies" },
			wantErr: `policy-sbom.spdx.json records the repository "ghcr.io/rancher/suse-security-policies/container-block-sysctl", which is not a policy under ghcr.io/kubewarden/policies`},
		{name: "OCI base that is a prefix of the owner", change: func(o *options, _ string) { o.ociBase = "ghcr.io/rancher" },
			wantErr: "which is not a policy under ghcr.io/rancher"},
		{name: "changed upstream SBOM", change: func(_ *options, dir string) {
			path := filepath.Join(dir, upstreamSBOMName)
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(path, append(data, '\n'), 0o600))
		}, wantErr: "does not record the SHA256 checksum"},
		{name: "short upstream commit", edits: []edit{{upstreamSBOMName, fixtureCommit, "5bbbfd0"}},
			wantErr: `upstream-policy-sbom.spdx.json records "5bbbfd0" as the version of SPDXRef-DocumentRoot-Directory-container-block-sysctl-1.0.6, but it must be a full commit hash`},
		{name: "no GENERATED_FROM", edits: []edit{{sbomName, `"GENERATED_FROM"`, `"OTHER"`}},
			wantErr: "policy-sbom.spdx.json does not record that SPDXRef-Package-container-block-sysctl is generated from"},
		{name: "other ociUrl annotation", edits: []edit{{metadataName,
			"io.kubewarden.policy.ociUrl: ghcr.io/rancher/suse-security-policies/container-block-sysctl",
			"io.kubewarden.policy.ociUrl: ghcr.io/rancher/suse-security-policies/other"}},
			wantErr: `the io.kubewarden.policy.ociUrl annotation is "ghcr.io/rancher/suse-security-policies/other"`},
		{name: "other policy version annotation", edits: []edit{{metadataName, "io.kubewarden.policy.version: 1.0.6", "io.kubewarden.policy.version: 1.0.5"}},
			wantErr: `the io.kubewarden.policy.version annotation is "1.0.5", but the release version "1.0.6" needs "1.0.6"`},
		{name: "no display name", edits: []edit{{metadataName, "  io.artifacthub.displayName: Container Block Sysctls\n", ""}},
			wantErr: "the policy metadata needs the annotations io.kubewarden.policy.title and io.artifacthub.displayName"},
		{name: "no upstream README", files: map[string]string{"../LICENSE": "Apache License\n"},
			wantErr: "README.md: not found"},
		{name: "upstream error", status: map[string]int{"questions-ui.yml": http.StatusInternalServerError},
			wantErr: "questions-ui.yml: unexpected status 500"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := newRelease(t, tt.edits...)
			o := testOptions(t, dir)
			if tt.change != nil {
				tt.change(&o, dir)
			}
			files := tt.files
			if files == nil {
				files = defaultUpstreamFiles()
			}
			rawURL, _ := newUpstream(t, files, tt.status)
			err := run(o, rawURL, &bytes.Buffer{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
			assert.NoDirExists(t, o.output, "a failed run must write nothing")
		})
	}
}

func TestBuildChartOptionalAnnotations(t *testing.T) {
	dir := newRelease(t,
		edit{metadataName, "contextAwareResources: []", "contextAwareResources:\n  - apiVersion: v1\n    kind: Namespace"},
		edit{metadataName, "  io.kubewarden.policy.ociUrl:", "  io.kubewarden.hidden-ui: 'True'\n  io.kubewarden.policy.ociUrl:"},
	)
	o := testOptions(t, dir)
	rawURL, _ := newUpstream(t, defaultUpstreamFiles(), nil)
	require.NoError(t, run(o, rawURL, &bytes.Buffer{}))
	chart := readFile(t, filepath.Join(o.output, chartFile))
	assert.Contains(t, chart, "  kubewarden/contextAwareResources: |\n    - apiVersion: v1\n      kind: Namespace\n")
	assert.Contains(t, chart, `  kubewarden/hidden-ui: "true"`)
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.6", "1.0.6", 0},
		{"1.0.5", "1.0.6", -1},
		{"1.0.10", "1.0.9", 1},
		{"1.0.6", "1.0.6+suse.1", -1},
		{"1.0.6+suse.2", "1.0.6+suse.10", -1},
		{"1.0.6+suse.1", "1.0.7", -1},
		{"1.0.7-rc.1", "1.0.7", -1},
	}
	for _, tt := range tests {
		got, err := compareVersions(tt.a, tt.b)
		require.NoError(t, err, "%s %s", tt.a, tt.b)
		assert.Equal(t, tt.want, got, "compareVersions(%q, %q)", tt.a, tt.b)
	}
	for _, bad := range []string{"v1.0.6", "1.0", "1.0.6+build.1", "1.0.6+suse.0", "1.0.6+suse.01"} {
		_, err := compareVersions(bad, "1.0.6")
		assert.Error(t, err, bad)
	}
}

func TestOptionsCheck(t *testing.T) {
	err := options{tag: "x"}.check(nil)
	require.Error(t, err)
	assert.Equal(t, "these flags are required and must not be empty: --release-dir, --policy-name, --release-version, --oci-tag, --oci-base, --upstream-repository, --output", err.Error())
	o := testOptions(t, "dir")
	require.Error(t, o.check([]string{"extra"}))
	require.NoError(t, o.check(nil))
	for _, name := range []string{"../charts", "a/b", ".hidden", "a..b"} {
		o.policyName = name
		assert.Error(t, o.check(nil), name)
	}
}
