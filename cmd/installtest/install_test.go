package installtest

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type fixture struct {
	root, home, releases, mock, installer string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, filename, _, _ := runtime.Caller(0)
	f := fixture{root, filepath.Join(root, "user home"), filepath.Join(root, "release files"), filepath.Join(root, "mocks"), filepath.Join(filepath.Dir(filename), "..", "..", "install.sh")}
	for _, dir := range []string{f.home, f.releases, f.mock} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	var sums strings.Builder
	for _, os := range []string{"linux", "darwin"} {
		for _, arch := range []string{"amd64", "arm64"} {
			name := "deepai-connect-" + os + "-" + arch
			body := "#!/bin/sh\nprintf '%s\\n' '" + name + "'\n"
			write(t, filepath.Join(f.releases, name), body, 0755)
			fmt.Fprintf(&sums, "%x  %s\n", sha256.Sum256([]byte(body)), name)
		}
	}
	write(t, filepath.Join(f.releases, "SHA256SUMS"), sums.String(), 0644)
	write(t, filepath.Join(f.mock, "uname"), "#!/bin/sh\ncase \"$1\" in -s) echo \"$TEST_OS\";; -m) echo \"$TEST_ARCH\";; *) exit 1;; esac\n", 0755)
	return f
}

func write(t *testing.T, path, contents string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func (f fixture) run(t *testing.T, extra map[string]string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("/bin/sh", append([]string{f.installer}, args...)...)
	// Never read or modify the real HOME, shell profile, or ZDOTDIR in a test.
	env := map[string]string{
		"HOME": f.home, "SHELL": "/bin/zsh", "PATH": f.mock + ":/usr/bin:/bin:/usr/sbin:/sbin",
		"TEST_OS": "Darwin", "TEST_ARCH": "arm64", "TEST_RELEASES": f.releases,
	}
	for k, v := range extra {
		env[k] = v
	}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestLocalReleaseSelection(t *testing.T) {
	for _, target := range [][4]string{
		{"Linux", "x86_64", "linux", "amd64"}, {"Linux", "aarch64", "linux", "arm64"},
		{"Darwin", "x86_64", "darwin", "amd64"}, {"Darwin", "arm64", "darwin", "arm64"},
	} {
		t.Run(target[0]+"_"+target[1], func(t *testing.T) {
			f := newFixture(t)
			bin := filepath.Join(f.home, "bin with spaces")
			out, err := f.run(t, map[string]string{"TEST_OS": target[0], "TEST_ARCH": target[1]}, "--from-dir", f.releases, "--bin-dir", bin, "--no-path")
			if err != nil {
				t.Fatalf("install: %v\n%s", err, out)
			}
			if read(t, filepath.Join(bin, "deepai-connect")) != read(t, filepath.Join(f.releases, "deepai-connect-"+target[2]+"-"+target[3])) {
				t.Fatal("installed wrong artifact")
			}
			if _, err := os.Stat(filepath.Join(f.home, ".zshrc")); !os.IsNotExist(err) {
				t.Fatal("--no-path modified startup files")
			}
		})
	}
}

func TestDownloadedBundleInstallsWithoutCheckoutOrNetwork(t *testing.T) {
	f := newFixture(t)
	installer := read(t, f.installer)
	f.installer = filepath.Join(f.releases, "install.sh")
	write(t, f.installer, installer, 0755)
	write(t, filepath.Join(f.mock, "curl"), "#!/bin/sh\nexit 99\n", 0755)
	out, err := f.run(t, nil, "--no-path")
	if err != nil {
		t.Fatalf("bundle install: %v\n%s", err, out)
	}
	if got := read(t, filepath.Join(f.home, ".local", "bin", "deepai-connect")); got != read(t, filepath.Join(f.releases, "deepai-connect-darwin-arm64")) {
		t.Fatal("bundle did not select the native binary")
	}
	if !strings.Contains(out, "setup --hub USER@HOST") || !strings.Contains(out, "deepai-connect status") {
		t.Fatal("installer did not provide the next step")
	}
}

func TestFailedChecksumPreservesPreviousInstallation(t *testing.T) {
	f := newFixture(t)
	if out, err := f.run(t, nil, "--from-dir", f.releases, "--no-path"); err != nil {
		t.Fatalf("initial install: %v\n%s", err, out)
	}
	bin := filepath.Join(f.home, ".local", "bin")
	previous := read(t, filepath.Join(bin, "deepai-connect"))
	write(t, filepath.Join(f.releases, "deepai-connect-darwin-arm64"), "corrupted artifact", 0755)
	if out, err := f.run(t, nil, "--from-dir", f.releases); err == nil || !strings.Contains(out, "checksum mismatch") {
		t.Fatalf("expected checksum failure: %v\n%s", err, out)
	}
	if got := read(t, filepath.Join(bin, "deepai-connect")); got != previous {
		t.Fatal("failed installation changed existing executable")
	}
	entries, err := os.ReadDir(bin)
	if err != nil || len(entries) != 2 {
		t.Fatalf("installer leaked staging files: %v, %v", entries, err)
	}
}

func TestGuardedPathSetupIsIdempotent(t *testing.T) {
	for _, shell := range []string{"zsh", "bash", "sh"} {
		t.Run(shell, func(t *testing.T) {
			f := newFixture(t)
			files := []string{".profile"}
			switch shell {
			case "zsh":
				files = []string{".zshrc", ".zprofile"}
			case "bash":
				files = []string{".bashrc", ".bash_profile"}
			}
			for _, file := range files {
				write(t, filepath.Join(f.home, file), "# keep this configuration\nexit 97\n", 0600)
			}
			bin := filepath.Join(f.home, "user's bin")
			for i := 0; i < 2; i++ {
				if out, err := f.run(t, map[string]string{"SHELL": "/bin/" + shell}, "--from-dir", f.releases, "--bin-dir", bin); err != nil {
					t.Fatalf("install %d: %v\n%s", i, err, out)
				}
			}
			for _, file := range files {
				contents := read(t, filepath.Join(f.home, file))
				if !strings.HasPrefix(contents, "# keep this configuration\nexit 97\n") || strings.Count(contents, "# deepai-connect PATH:") != 1 {
					t.Fatalf("modified existing config or duplicated PATH: %s", contents)
				}
				block := contents[strings.Index(contents, "# deepai-connect PATH:"):]
				cmd := exec.Command("/bin/sh")
				cmd.Env = []string{"PATH=/usr/bin:/bin"}
				cmd.Stdin = strings.NewReader(block + block + "printf '%s' \"$PATH\"\n")
				out, err := cmd.CombinedOutput()
				if err != nil || string(out) != bin+":/usr/bin:/bin" {
					t.Fatalf("PATH guard is not safe/idempotent: %v, %s", err, out)
				}
			}
		})
	}
}

func TestUnsafeDestinationRefused(t *testing.T) {
	for _, kind := range []string{"binary symlink", "directory symlink", "ordinary file", "directory"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			bin := filepath.Join(f.home, "bin")
			if err := os.Mkdir(bin, 0700); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(f.root, "keep")
			write(t, outside, "keep me", 0600)
			dest := filepath.Join(bin, "deepai-connect")
			var err error
			switch kind {
			case "binary symlink":
				err = os.Symlink(outside, dest)
			case "directory symlink":
				bin = filepath.Join(f.home, "linked-bin")
				err = os.Symlink(filepath.Join(f.home, "bin"), bin)
			case "ordinary file":
				write(t, dest, "notes", 0600)
			case "directory":
				err = os.Mkdir(dest, 0700)
			}
			if err != nil {
				t.Fatal(err)
			}
			if out, err := f.run(t, nil, "--from-dir", f.releases, "--bin-dir", bin); err == nil || !strings.Contains(out, "refusing") {
				t.Fatalf("unsafe destination accepted: %v\n%s", err, out)
			}
			if read(t, outside) != "keep me" {
				t.Fatal("modified symlink target")
			}
		})
	}
}

func TestDownloadsPublishedReleaseWithHTTPS(t *testing.T) {
	for _, version := range []string{"latest", "v1.2.3"} {
		t.Run(version, func(t *testing.T) {
			f := newFixture(t)
			write(t, filepath.Join(f.mock, "curl"), `#!/bin/sh
set -eu
[ "$1" = --proto ] && [ "$2" = '=https' ] && [ "$3" = --proto-redir ] && [ "$4" = '=https' ]
while [ "$1" != --output ]; do shift; done
output=$2
url=$3
printf '%s\n' "$url" >> "$TEST_URL_LOG"
case "$url" in https://github.com/deepai-cloud/deepai-connect/releases/*) ;; *) exit 1;; esac
cp "$TEST_RELEASES/${url##*/}" "$output"
`, 0755)
			log := filepath.Join(f.root, "urls")
			args := []string{"--no-path"}
			if version != "latest" {
				args = append(args, "--version", version)
			}
			if out, err := f.run(t, map[string]string{"TEST_URL_LOG": log}, args...); err != nil {
				t.Fatalf("download install: %v\n%s", err, out)
			}
			prefix := "https://github.com/deepai-cloud/deepai-connect/releases/download/" + version + "/"
			if version == "latest" {
				prefix = "https://github.com/deepai-cloud/deepai-connect/releases/latest/download/"
			}
			if got := read(t, log); got != prefix+"SHA256SUMS\n"+prefix+"deepai-connect-darwin-arm64\n" {
				t.Fatalf("unexpected download URLs: %s", got)
			}
		})
	}
}

func TestFromSourceBuildEnvironment(t *testing.T) {
	f := newFixture(t)
	write(t, filepath.Join(f.mock, "go"), `#!/bin/sh
set -eu
[ "$GOTOOLCHAIN" = auto ] && [ "$GOWORK" = off ] && [ "$CGO_ENABLED" = 0 ]
[ "$GOOS" = darwin ] && [ "$GOARCH" = arm64 ]
[ "$GOAMD64" = v1 ] && [ "$GOARM64" = v8.0 ]
[ -z "$GOFLAGS" ] && [ -z "$GOEXPERIMENT" ]
[ "$1" = build ]
while [ "$1" != -o ]; do shift; done
cp "$TEST_RELEASES/deepai-connect-darwin-arm64" "$2"
`, 0755)
	if out, err := f.run(t, nil, "--from-source", "--no-path"); err != nil {
		t.Fatalf("source install: %v\n%s", err, out)
	}
	if got := read(t, filepath.Join(f.home, ".local", "bin", "deepai-connect")); !strings.Contains(got, "darwin-arm64") {
		t.Fatal("source build did not install result")
	}
}

func TestMissingReleaseHasActionableError(t *testing.T) {
	f := newFixture(t)
	write(t, filepath.Join(f.mock, "curl"), "#!/bin/sh\nexit 22\n", 0755)
	if out, err := f.run(t, nil); err == nil || !strings.Contains(out, "may not publish darwin/arm64") || !strings.Contains(out, "--from-source") {
		t.Fatalf("expected actionable missing release error: %v\n%s", err, out)
	}
}

func TestUnsupportedPlatformDoesNotWrite(t *testing.T) {
	f := newFixture(t)
	if out, err := f.run(t, map[string]string{"TEST_OS": "Windows"}, "--from-dir", f.releases); err == nil || !strings.Contains(out, "supported systems") {
		t.Fatalf("unsupported system accepted: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(f.home, ".local")); !os.IsNotExist(err) {
		t.Fatal("unsupported installation wrote to disk")
	}
}

func TestUpgradeRollbackAndUninstallPreserveUserState(t *testing.T) {
	f := newFixture(t)
	bin := filepath.Join(f.home, ".local", "bin")
	install := func(args ...string) {
		t.Helper()
		if out, err := f.run(t, nil, args...); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	install("--from-dir", f.releases, "--no-path")
	old := read(t, filepath.Join(bin, "deepai-connect"))
	body := old + "# upgraded\n"
	write(t, filepath.Join(f.releases, "deepai-connect-darwin-arm64"), body, 0755)
	write(t, filepath.Join(f.releases, "SHA256SUMS"), fmt.Sprintf("%x  deepai-connect-darwin-arm64\n", sha256.Sum256([]byte(body))), 0600)
	install("--from-dir", f.releases, "--no-path")
	install("--from-dir", f.releases, "--no-path")
	if got := read(t, filepath.Join(bin, ".deepai-connect.previous")); got != old {
		t.Fatal("repeat install lost useful rollback binary")
	}
	install("--rollback")
	if got := read(t, filepath.Join(bin, "deepai-connect")); got != old {
		t.Fatal("rollback did not restore previous binary")
	}
	if got := read(t, filepath.Join(bin, ".deepai-connect.previous")); got != body {
		t.Fatal("rollback did not preserve replaced binary")
	}
	state := filepath.Join(f.home, "enrolled-identity")
	write(t, state, "preserve identity", 0600)
	profile := filepath.Join(f.home, ".zshrc")
	write(t, profile, "preserve user PATH", 0600)
	install("--uninstall")
	install("--uninstall")
	if read(t, state) != "preserve identity" || read(t, profile) != "preserve user PATH" {
		t.Fatal("uninstall modified unrelated user state")
	}
	entries, err := os.ReadDir(bin)
	if err != nil || len(entries) != 0 {
		t.Fatalf("uninstall left managed artifacts: %v, %v", entries, err)
	}
}

func TestUninstallRefusesRegisteredOrChangedCLI(t *testing.T) {
	for _, kind := range []string{"login registration", "changed binary", "changed backup", "receipt symlink"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			if out, err := f.run(t, nil, "--from-dir", f.releases, "--no-path"); err != nil {
				t.Fatalf("install: %v\n%s", err, out)
			}
			bin := filepath.Join(f.home, ".local", "bin")
			dest := filepath.Join(bin, "deepai-connect")
			switch kind {
			case "login registration":
				dir := filepath.Join(f.home, "Library", "LaunchAgents")
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				write(t, filepath.Join(dir, "cloud.deepai.connect.vm.worker.plist"), "XML escaped or arbitrary registered binary", 0600)
			case "changed binary":
				write(t, dest, "changed", 0755)
			case "changed backup":
				write(t, filepath.Join(bin, ".deepai-connect.previous"), "changed", 0755)
				write(t, filepath.Join(bin, ".deepai-connect.previous.sha256"), "wrong", 0600)
			case "receipt symlink":
				if err := os.Remove(filepath.Join(bin, ".deepai-connect.sha256")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(dest, filepath.Join(bin, ".deepai-connect.sha256")); err != nil {
					t.Fatal(err)
				}
			}
			before := read(t, dest)
			if out, err := f.run(t, nil, "--uninstall"); err == nil {
				t.Fatalf("unsafe uninstall accepted: %s", out)
			}
			if read(t, dest) != before {
				t.Fatal("failed uninstall changed executable")
			}
		})
	}
}

func TestRollbackRequiresVerifiedPreviousBinary(t *testing.T) {
	f := newFixture(t)
	if out, err := f.run(t, nil, "--from-dir", f.releases, "--no-path"); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	bin := filepath.Join(f.home, ".local", "bin")
	before := read(t, filepath.Join(bin, "deepai-connect"))
	if out, err := f.run(t, nil, "--rollback"); err == nil || !strings.Contains(out, "no managed CLI or backup") {
		t.Fatalf("missing backup accepted: %v %s", err, out)
	}
	if read(t, filepath.Join(bin, "deepai-connect")) != before {
		t.Fatal("failed rollback changed CLI")
	}
}

func TestReplacementFailurePreservesInstalledBinary(t *testing.T) {
	f := newFixture(t)
	if out, err := f.run(t, nil, "--from-dir", f.releases, "--no-path"); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	bin := filepath.Join(f.home, ".local", "bin")
	before := read(t, filepath.Join(bin, "deepai-connect"))
	body := before + "# replacement\n"
	write(t, filepath.Join(f.releases, "deepai-connect-darwin-arm64"), body, 0755)
	write(t, filepath.Join(f.releases, "SHA256SUMS"), fmt.Sprintf("%x  deepai-connect-darwin-arm64\n", sha256.Sum256([]byte(body))), 0600)
	write(t, filepath.Join(f.mock, "mv"), `#!/bin/sh
for arg do last=$arg; done
case "$last" in */deepai-connect) exit 73 ;; esac
exec /bin/mv "$@"
`, 0755)
	if out, err := f.run(t, nil, "--from-dir", f.releases, "--no-path"); err == nil {
		t.Fatalf("failed replacement accepted: %s", out)
	}
	if read(t, filepath.Join(bin, "deepai-connect")) != before {
		t.Fatal("failed replacement changed installed executable")
	}
	for _, entry := range mustReadDir(t, bin) {
		if strings.HasPrefix(entry.Name(), ".deepai-connect-install.") {
			t.Fatal("failed replacement leaked staging files")
		}
	}
}

func mustReadDir(t *testing.T, path string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func TestInterruptedReceiptCommitCanRecoverAndRollback(t *testing.T) {
	for _, receipt := range []string{".deepai-connect.sha256", ".deepai-connect.previous.sha256"} {
		t.Run(receipt, func(t *testing.T) {
			f := newFixture(t)
			if out, err := f.run(t, nil, "--from-dir", f.releases, "--no-path"); err != nil {
				t.Fatalf("install: %v\n%s", err, out)
			}
			bin := filepath.Join(f.home, ".local", "bin")
			before := read(t, filepath.Join(bin, "deepai-connect"))
			body := before + "# replacement\n"
			write(t, filepath.Join(f.releases, "deepai-connect-darwin-arm64"), body, 0755)
			write(t, filepath.Join(f.releases, "SHA256SUMS"), fmt.Sprintf("%x  deepai-connect-darwin-arm64\n", sha256.Sum256([]byte(body))), 0600)
			mock := filepath.Join(f.mock, "mv")
			write(t, mock, "#!/bin/sh\nfor arg do last=$arg; done\ncase \"$last\" in */"+receipt+") exit 73 ;; esac\nexec /bin/mv \"$@\"\n", 0755)
			if out, err := f.run(t, nil, "--from-dir", f.releases, "--no-path"); err == nil {
				t.Fatalf("receipt failure accepted: %s", out)
			}
			if err := os.Remove(mock); err != nil {
				t.Fatal(err)
			}
			if out, err := f.run(t, nil, "--rollback"); err != nil {
				t.Fatalf("receipt recovery/rollback failed: %v\n%s", err, out)
			}
			if read(t, filepath.Join(bin, "deepai-connect")) != before {
				t.Fatal("recovery did not restore the previous binary")
			}
			if _, err := os.Stat(filepath.Join(bin, ".deepai-connect.transaction")); !os.IsNotExist(err) {
				t.Fatal("successful recovery left transaction")
			}
		})
	}
}

func TestUpgradeRefusesChangedBackup(t *testing.T) {
	f := newFixture(t)
	if out, err := f.run(t, nil, "--from-dir", f.releases, "--no-path"); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	bin := filepath.Join(f.home, ".local", "bin")
	before := read(t, filepath.Join(bin, "deepai-connect"))
	backup := filepath.Join(bin, ".deepai-connect.previous")
	write(t, backup, "unexpected private file", 0600)
	if out, err := f.run(t, nil, "--from-dir", f.releases, "--no-path"); err == nil {
		t.Fatalf("unexpected backup accepted: %s", out)
	}
	if read(t, backup) != "unexpected private file" || read(t, filepath.Join(bin, "deepai-connect")) != before {
		t.Fatal("upgrade changed unexpected backup or binary")
	}
}
