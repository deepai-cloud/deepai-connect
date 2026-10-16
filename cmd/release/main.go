// release builds the standalone DeepAI Connect distribution. It is never shipped.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/deepai-cloud/deepai-connect/internal/buildinfo"
)

const (
	binary  = "deepai-connect"
	command = "./cmd/" + binary
)

type target struct{ OS, Arch string }

var targets = []target{{"linux", "arm64"}, {"linux", "amd64"}, {"darwin", "arm64"}, {"darwin", "amd64"}}

type artifact struct {
	Name   string `json:"name"`
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type manifest struct {
	Product   string     `json:"product"`
	Version   string     `json:"version"`
	Command   string     `json:"command"`
	Artifacts []artifact `json:"artifacts"`
}
type builder func(target, string, string) error

func main() {
	out := flag.String("out", "dist", "artifact directory")
	version := flag.String("version", buildinfo.Version, "embedded version")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "release: unexpected positional arguments")
		os.Exit(1)
	}
	installer, err := os.ReadFile("install.sh")
	if err != nil {
		fmt.Fprintln(os.Stderr, "release: run from the project root containing install.sh:", err)
		os.Exit(1)
	}
	if err := build(*out, *version, installer, compile); err != nil {
		fmt.Fprintln(os.Stderr, "release:", err)
		os.Exit(1)
	}
}

func (t target) filename() string {
	return binary + "-" + t.OS + "-" + t.Arch
}

func releaseFiles() map[string]bool {
	files := map[string]bool{"SHA256SUMS": true, "manifest.json": true, "install.sh": true}
	for _, t := range targets {
		files[t.filename()] = true
	}
	return files
}

func build(dir, version string, installer []byte, compile builder) error {
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`).MatchString(version) {
		return fmt.Errorf("invalid version: use 1–64 letters, digits, dots, underscores, plus or minus")
	}
	dest, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if err := checkOutput(dest); err != nil {
		return err
	}
	parent := filepath.Dir(dest)
	if err := os.MkdirAll(parent, 0755); err != nil {
		return err
	}
	// Stage beside the destination so the complete release can replace it.
	stage, err := os.MkdirTemp(parent, ".deepai-connect-build-")
	if err != nil {
		return err
	}
	defer removeOutput(stage)
	m := manifest{Product: "connect", Version: version, Command: command}
	var sums strings.Builder
	for _, t := range targets {
		name := t.filename()
		path := filepath.Join(stage, name)
		if err := compile(t, version, path); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if err := os.Chmod(path, 0755); err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		digest := fmt.Sprintf("%x", sha256.Sum256(data))
		m.Artifacts = append(m.Artifacts, artifact{name, t.OS, t.Arch, digest, int64(len(data))})
		fmt.Fprintf(&sums, "%s  %s\n", digest, name)
	}
	if err := os.WriteFile(filepath.Join(stage, "install.sh"), installer, 0755); err != nil {
		return err
	}
	fmt.Fprintf(&sums, "%x  install.sh\n", sha256.Sum256(installer))
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	for name, contents := range map[string][]byte{"SHA256SUMS": []byte(sums.String()), "manifest.json": append(data, '\n')} {
		path := filepath.Join(stage, name)
		if err := os.WriteFile(path, contents, 0644); err != nil {
			return err
		}
		if err := os.Chmod(path, 0644); err != nil {
			return err
		}
	}
	if err := os.Chmod(stage, 0755); err != nil {
		return err
	}
	if err := installRelease(stage, dest); err != nil {
		return err
	}
	for _, a := range m.Artifacts {
		fmt.Println(filepath.Join(dest, a.Name))
	}
	return nil
}

func compile(t target, version, path string) error {
	c := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags", "-s -w -X github.com/deepai-cloud/deepai-connect/internal/buildinfo.Version="+version, "-o", path, command)
	c.Env = buildEnv(t)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	return c.Run()
}

// Generic release names promise baseline CPUs, regardless of the builder's
// local optimization, workspace, feature-tag, or experimental runtime settings.
func buildEnv(t target) []string {
	var env []string
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		switch strings.ToUpper(key) {
		case "GOOS", "GOARCH", "GOAMD64", "GOARM64", "CGO_ENABLED", "GOWORK", "GOFLAGS", "GOEXPERIMENT":
		default:
			env = append(env, value)
		}
	}
	return append(env, "GOOS="+t.OS, "GOARCH="+t.Arch, "GOAMD64=v1", "GOARM64=v8.0", "CGO_ENABLED=0", "GOWORK=off", "GOFLAGS=", "GOEXPERIMENT=")
}

// Only release artifacts may exist in the output directory; never sweep arbitrary files.
func checkOutput(dir string) error {
	allowed := releaseFiles()
	if err := noLinks(dir); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !allowed[entry.Name()] || !info.Mode().IsRegular() {
			return fmt.Errorf("unexpected release output (leave it intact): %s", filepath.Join(dir, entry.Name()))
		}
	}
	return nil
}

func removeOutput(dir string) error {
	if err := checkOutput(dir); err != nil {
		return err
	}
	for name := range releaseFiles() {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.Remove(dir); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Build the entire release before replacing its directory, with rollback on rename failure.
func installRelease(stage, dest string) error {
	if err := checkOutput(stage); err != nil {
		return err
	}
	if err := checkOutput(dest); err != nil {
		return err
	}
	backup := ""
	if _, err := os.Lstat(dest); err == nil {
		backup, err = os.MkdirTemp(filepath.Dir(dest), ".deepai-previous-")
		if err != nil {
			return err
		}
		if err := os.Remove(backup); err != nil {
			return err
		}
		if err := os.Rename(dest, backup); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(stage, dest); err != nil {
		if backup != "" {
			return errors.Join(err, os.Rename(backup, dest))
		}
		return err
	}
	if backup != "" {
		if err := removeOutput(backup); err != nil {
			return fmt.Errorf("release installed; could not remove previous artifacts at %s: %w", backup, err)
		}
	}
	return nil
}

func noLinks(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for {
		fi, err := os.Lstat(path)
		if err == nil && fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink: %s", path)
		}
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}
