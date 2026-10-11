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
	ImportPath, Name                        string
	Deps, GoFiles, CgoFiles, IgnoredGoFiles []string
	Error                                   *struct{ Err string }
	Standard                                bool
	Module                                  *struct {
		Path    string
		Replace *json.RawMessage
	}
}

func allowed(path string) bool {
	for _, root := range []string{"internal/connect", "internal/runtime/docker", "internal/platform", "internal/contract/edgeaccess", "internal/buildinfo"} {
		if path == module+root || strings.HasPrefix(path, module+root+"/") {
			return true
		}
	}
	return false
}

func allowedPackage(path string) bool {
	// go list appends bracketed package identities for test variants.
	path, _, testVariant := strings.Cut(path, " [")
	path = strings.TrimSuffix(path, ".test")
	if testVariant {
		path = strings.TrimSuffix(path, "_test")
	}
	return allowed(path) || path == module+"cmd/deepai-connect" || path == module+"cmd/release" || path == module+"internal/architecture"
}

// One graph per target covers the executable, support packages and all tests.
// Every nonstandard package must belong to this module or its sole dependency.
func TestConnectDependencies(t *testing.T) {
	const command = module + "cmd/deepai-connect"
	seen := map[[2]string]bool{}
	for _, target := range [][2]string{{"linux", "amd64"}, {"linux", "arm64"}, {runtime.GOOS, runtime.GOARCH}} {
		if seen[target] {
			continue
		}
		seen[target] = true
		t.Run(target[0]+"/"+target[1], func(t *testing.T) {
			t.Parallel()
			found := false
			for _, p := range packages(t, target[0], target[1], "-deps", "-test", "./...") {
				// -deps already lists every transitive dependency as a package.
				if !p.Standard {
					if p.Module == nil || p.Module.Replace != nil {
						t.Errorf("package %s lacks an unreplaced module", p.ImportPath)
					} else if p.Module.Path == strings.TrimSuffix(module, "/") {
						if !allowedPackage(p.ImportPath) {
							t.Errorf("unapproved repository package %s", p.ImportPath)
						}
					} else if p.Module.Path != "golang.org/x/sys" {
						t.Errorf("unapproved dependency module %s", p.Module.Path)
					}
				}
				if p.ImportPath == command {
					found = true
					if p.Name != "main" || len(p.GoFiles) == 0 {
						t.Fatal("DeepAI Connect is not an executable command")
					}
				}
				if strings.Contains(p.ImportPath, " [") || strings.HasSuffix(p.ImportPath, ".test") || (p.ImportPath != command && !allowed(p.ImportPath)) {
					continue
				}
				for _, dep := range p.Deps {
					if strings.HasPrefix(dep, module) && dep != command && !allowed(dep) {
						t.Errorf("%s includes unapproved package %s", p.ImportPath, dep)
					}
				}
			}
			if target[0] == "linux" && (target[1] == "amd64" || target[1] == "arm64") && !found {
				t.Fatal("missing DeepAI Connect command")
			}
		})
	}
}

func TestStandaloneModule(t *testing.T) {
	var mod struct {
		Module  struct{ Path string }
		Require []struct{ Path string }
		Replace []json.RawMessage
	}
	if err := json.Unmarshal(goOutput(t, runtime.GOOS, runtime.GOARCH, "mod", "edit", "-json"), &mod); err != nil {
		t.Fatal(err)
	}
	if mod.Module.Path != strings.TrimSuffix(module, "/") || len(mod.Require) != 1 || mod.Require[0].Path != "golang.org/x/sys" || len(mod.Replace) != 0 {
		t.Fatal("DeepAI Connect must be a standalone module with only golang.org/x/sys and no replacements")
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
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = filepath.Dir(filepath.Dir(filepath.Dir(file)))
	for _, v := range os.Environ() {
		key, _, _ := strings.Cut(v, "=")
		switch strings.ToUpper(key) {
		case "GOOS", "GOARCH", "CGO_ENABLED", "GOWORK", "GOFLAGS", "GOENV", "GOPROXY", "GOSUMDB":
		default:
			cmd.Env = append(cmd.Env, v)
		}
	}
	// Use the test's toolchain and cached dependencies; do not consult a parent
	// workspace, user build flags, or the network while auditing distributions.
	cmd.Env = append(cmd.Env, "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0", "GOWORK=off", "GOFLAGS=", "GOENV=off", "GOPROXY=off", "GOSUMDB=off")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go %v for %s/%s: %v\n%s", args, goos, goarch, err, stderr.String())
	}
	return out
}
