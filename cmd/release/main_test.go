package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const testInstaller = "#!/bin/sh\necho installer\n"

func fakeBuild(t target, version, path string) error {
	return os.WriteFile(path, []byte(strings.Join([]string{command, t.OS, t.Arch, version}, "\n")), 0755)
}

func TestReleaseMatrix(t *testing.T) {
	want := []string{"deepai-connect-linux-arm64", "deepai-connect-linux-amd64", "deepai-connect-darwin-arm64", "deepai-connect-darwin-amd64"}
	dir := filepath.Join(tempDir(t), "releases", "dist")
	if err := build(dir, "0.2.0", []byte(testInstaller), fakeBuild); err != nil {
		t.Fatal(err)
	}
	var m manifest
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil || json.Unmarshal(data, &m) != nil {
		t.Fatalf("invalid manifest: %v", err)
	}
	if m.Product != "connect" || m.Version != "0.2.0" || m.Command != "./cmd/deepai-connect" {
		t.Fatalf("wrong distribution identity: %+v", m)
	}
	var got []string
	var sums strings.Builder
	for _, a := range m.Artifacts {
		got = append(got, a.Name)
		data, err := os.ReadFile(filepath.Join(dir, a.Name))
		if err != nil {
			t.Fatal(err)
		}
		if a.SHA256 != fmt.Sprintf("%x", sha256.Sum256(data)) || a.Size != int64(len(data)) {
			t.Fatalf("manifest does not describe artifact %s", a.Name)
		}
		if string(data) != strings.Join([]string{m.Command, a.OS, a.Arch, m.Version}, "\n") {
			t.Fatalf("wrong target metadata: %+v", a)
		}
		fmt.Fprintf(&sums, "%s  %s\n", a.SHA256, a.Name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("targets: got %v want %v", got, want)
	}
	fmt.Fprintf(&sums, "%x  install.sh\n", sha256.Sum256([]byte(testInstaller)))
	data, err = os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil || string(data) != sums.String() {
		t.Fatal("checksum and manifest allowlists differ")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != len(want)+3 {
		t.Fatalf("unexpected shipped files: %v", entries)
	}
	entries, err = os.ReadDir(filepath.Dir(dir))
	if err != nil || len(entries) != 1 || entries[0].Name() != "dist" {
		t.Fatalf("release leaked staging or unrelated artifacts: %v", entries)
	}
}

func TestFailedBuildPreservesPreviousRelease(t *testing.T) {
	dir := filepath.Join(tempDir(t), "dist")
	if err := build(dir, "0.1.0", []byte(testInstaller), fakeBuild); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, dir)
	calls := 0
	err := build(dir, "0.2.0", []byte(testInstaller), func(target target, version, path string) error {
		calls++
		if calls == 2 {
			if err := os.WriteFile(path, []byte("partial executable"), 0600); err != nil {
				t.Fatal(err)
			}
			return errors.New("compiler failed")
		}
		return fakeBuild(target, version, path)
	})
	if err == nil || !strings.Contains(err.Error(), "compiler failed") {
		t.Fatalf("expected compiler failure: %v", err)
	}
	if got := snapshot(t, dir); !reflect.DeepEqual(before, got) {
		t.Fatal("failed release modified previous release")
	}
	entries, _ := os.ReadDir(filepath.Dir(dir))
	if len(entries) != 1 {
		t.Fatalf("failed build left staging files: %v", entries)
	}
	if err := build(dir, "0.2.0", []byte(testInstaller), fakeBuild); err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(before, snapshot(t, dir)) {
		t.Fatal("successful release did not replace previous release")
	}
	entries, _ = os.ReadDir(filepath.Dir(dir))
	if len(entries) != 1 {
		t.Fatalf("successful replacement left previous artifacts: %v", entries)
	}
}

func TestUnexpectedOutputFailsBeforeBuilding(t *testing.T) {
	for _, name := range []string{"private.json", "deepai-connect-windows-amd64.exe", "nested-directory"} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(tempDir(t), "dist")
			if err := os.Mkdir(dir, 0755); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, name)
			if name == "nested-directory" {
				if err := os.Mkdir(path, 0755); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte("keep me"), 0600); err != nil {
				t.Fatal(err)
			}
			err := build(dir, "0.2.0", []byte(testInstaller), func(target, string, string) error {
				t.Fatal("built before validating the release output")
				return nil
			})
			if err == nil {
				t.Fatal("accepted unexpected release contents")
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatal("removed unexpected user file", err)
			}
		})
	}
}

func TestOutputSymlinksRefused(t *testing.T) {
	for _, where := range []string{"ancestor", "output", "artifact", "metadata"} {
		t.Run(where, func(t *testing.T) {
			root := tempDir(t)
			dir := filepath.Join(root, "releases", "dist")
			outside := filepath.Join(root, "outside")
			if err := os.Mkdir(outside, 0755); err != nil {
				t.Fatal(err)
			}
			path := dir
			switch where {
			case "ancestor":
				path = filepath.Dir(dir)
			case "artifact":
				path = filepath.Join(dir, "deepai-connect-linux-arm64")
			case "metadata":
				path = filepath.Join(dir, "manifest.json")
			}
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, path); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			if err := build(dir, "0.2.0", []byte(testInstaller), fakeBuild); err == nil {
				t.Fatal("followed output symlink")
			}
			entries, err := os.ReadDir(outside)
			if err != nil || len(entries) != 0 {
				t.Fatal("wrote through symlink")
			}
		})
	}
}

func TestInvalidVersionDoesNotWrite(t *testing.T) {
	for _, version := range []string{"", "bad version", "-X=oops", strings.Repeat("a", 65)} {
		dir := filepath.Join(tempDir(t), "missing-parent", "release")
		if err := build(dir, version, []byte(testInstaller), fakeBuild); err == nil {
			t.Fatalf("accepted invalid version %q", version)
		}
		if _, err := os.Stat(filepath.Dir(dir)); !os.IsNotExist(err) {
			t.Fatal("invalid version wrote to disk")
		}
	}
}

func TestReleaseEnvironmentUsesPortableTargets(t *testing.T) {
	for key, value := range map[string]string{
		"GOOS": "plan9", "GOARCH": "386", "GOAMD64": "v4", "GOARM64": "v9.5,lse",
		"CGO_ENABLED": "1", "GOWORK": "/other/go.work", "GOFLAGS": "-race -tags=developer",
		"GOEXPERIMENT": "arenas", "GOTOOLCHAIN": "go1.26.9", "DEEPAI_RELEASE_ENV_TEST": "retain",
	} {
		t.Setenv(key, value)
	}
	for _, target := range targets {
		t.Run(target.filename(), func(t *testing.T) {
			want := map[string]string{
				"GOOS": target.OS, "GOARCH": target.Arch, "GOAMD64": "v1", "GOARM64": "v8.0",
				"CGO_ENABLED": "0", "GOWORK": "off", "GOFLAGS": "", "GOEXPERIMENT": "",
				"GOTOOLCHAIN": "go1.26.9", "DEEPAI_RELEASE_ENV_TEST": "retain",
			}
			env := map[string]string{}
			for _, entry := range buildEnv(target) {
				key, value, _ := strings.Cut(entry, "=")
				key = strings.ToUpper(key)
				if _, relevant := want[key]; !relevant {
					continue
				}
				if _, duplicate := env[key]; duplicate {
					t.Fatalf("duplicate environment key %s", key)
				}
				env[key] = value
			}
			for key, expected := range want {
				if got, ok := env[key]; !ok || got != expected {
					t.Errorf("%s: got %q (present %v), want %q", key, got, ok, expected)
				}
			}
		})
	}
}

func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]string{}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		result[entry.Name()] = string(data)
	}
	return result
}

func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}
