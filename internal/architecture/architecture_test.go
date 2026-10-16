package architecture_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const module = "github.com/deepai-cloud/deepai-connect/"

type pkg struct {
	ImportPath, Name                  string
	GoFiles, CgoFiles, IgnoredGoFiles []string
	Error                             *struct{ Err string }
}

func TestLinuxCommand(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			t.Parallel()
			ps := packages(t, "linux", arch, "./cmd/deepai-connect")
			if len(ps) != 1 || ps[0].ImportPath != module+"cmd/deepai-connect" || ps[0].Name != "main" || len(ps[0].GoFiles) == 0 {
				t.Fatal("missing standalone Linux command")
			}
		})
	}
}

func TestStandaloneModule(t *testing.T) {
	var mod struct {
		Module  struct{ Path string }
		Replace []json.RawMessage
	}
	if err := json.Unmarshal(goOutput(t, runtime.GOOS, runtime.GOARCH, "mod", "edit", "-json"), &mod); err != nil {
		t.Fatal(err)
	}
	if mod.Module.Path != strings.TrimSuffix(module, "/") || len(mod.Replace) != 0 {
		t.Fatal("DeepAI Connect must be a standalone module with no replacements")
	}
}

func TestConnectExcludedOnUnsupportedTargets(t *testing.T) {
	for _, target := range [][2]string{{"darwin", "arm64"}, {"darwin", "amd64"}, {"windows", "amd64"}, {"linux", "386"}, {"linux", "arm"}} {
		t.Run(target[0]+"/"+target[1], func(t *testing.T) {
			t.Parallel()
			ps := packages(t, target[0], target[1], "-e", "./cmd/deepai-connect")
			if len(ps) != 1 || ps[0].Error == nil || len(ps[0].GoFiles)+len(ps[0].CgoFiles) != 0 || len(ps[0].IgnoredGoFiles) == 0 {
				t.Fatal("deepai-connect must be excluded by build constraints outside Linux amd64/arm64")
			}
		})
	}
}

func packages(t *testing.T, goos, goarch string, args ...string) []pkg {
	t.Helper()
	var result []pkg
	dec := json.NewDecoder(bytes.NewReader(goOutput(t, goos, goarch, append([]string{"list", "-json"}, args...)...)))
	for {
		var p pkg
		if err := dec.Decode(&p); err == io.EOF {
			return result
		} else if err != nil {
			t.Fatal(err)
		}
		result = append(result, p)
	}
}

func goOutput(t *testing.T, goos, goarch string, args ...string) []byte {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate repository")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), args...)
	cmd.Dir = filepath.Dir(filepath.Dir(filepath.Dir(file)))
	for _, v := range os.Environ() {
		key, _, _ := strings.Cut(v, "=")
		switch strings.ToUpper(key) {
		case "GOOS", "GOARCH", "CGO_ENABLED", "GOWORK", "GOFLAGS", "GOENV", "GOPROXY", "GOSUMDB", "GOTOOLCHAIN":
		default:
			cmd.Env = append(cmd.Env, v)
		}
	}
	// Use the test's toolchain and cached dependencies; do not consult a parent
	// workspace, user build flags, or the network while auditing distributions.
	cmd.Env = append(cmd.Env, "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0", "GOWORK=off", "GOFLAGS=", "GOENV=off", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go %v for %s/%s: %v\n%s", args, goos, goarch, err, stderr.String())
	}
	return out
}
