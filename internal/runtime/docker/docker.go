// Package docker provides bounded, pinned local Docker transport for DeepAI Connect.
package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/platform"
)

// Runner uses argument vectors only: no shell, scripts, or command interpolation.
type Runner func(context.Context, []byte, ...string) ([]byte, error)

func Run(ctx context.Context, input []byte, args ...string) ([]byte, error) {
	return runDocker(ctx, "", input, args...)
}

// LocalRunner pins every request to the socket verified during preflight. A
// context switch must never redirect later mutations.
func LocalRunner(endpoint string) Runner {
	return func(ctx context.Context, input []byte, args ...string) ([]byte, error) {
		if !localEndpoint(endpoint) {
			return nil, errors.New("a verified local Docker endpoint is required")
		}
		return runDocker(ctx, endpoint, input, args...)
	}
}

func localEndpoint(host string) bool {
	return strings.HasPrefix(host, "unix:///") || strings.HasPrefix(host, "npipe:////./pipe/")
}

func Command(ctx context.Context, endpoint string, args ...string) (*exec.Cmd, error) {
	if len(args) >= 2 && args[0] == "--host" {
		if endpoint != "" && endpoint != args[1] {
			return nil, errors.New("Docker endpoint differs from the pinned socket")
		}
		endpoint, args = args[1], args[2:]
	}
	if len(args) == 0 {
		return nil, errors.New("Docker command is required")
	}
	if endpoint == "" {
		return exec.CommandContext(ctx, platform.DockerPath(), args...), nil
	}
	if !localEndpoint(endpoint) {
		return nil, errors.New("only local Docker sockets are supported")
	}
	cmd := exec.CommandContext(ctx, platform.DockerPath(), append([]string{"--host", endpoint}, args...)...)
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		switch strings.ToUpper(key) {
		case "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH":
		default:
			cmd.Env = append(cmd.Env, value)
		}
	}
	return cmd, nil
}

func runDocker(ctx context.Context, endpoint string, input []byte, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cmd, err := Command(ctx, endpoint, args...)
	if err != nil {
		return nil, err
	}
	cmd.Stdin = bytes.NewReader(input)
	var out limitedBuffer
	cmd.Stdout = &out
	// Docker exec may return credentials. Never include stderr or argv in errors.
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("Docker %s failed (check local Docker access): %w", args[0], err)
	}
	return out.Bytes(), nil
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 8<<20 {
		return 0, errors.New("command output exceeded 8 MiB")
	}
	return b.Buffer.Write(p)
}

type Client struct {
	Run      Runner
	Endpoint string
}

func (d Client) JSON(ctx context.Context, dst any, args ...string) error {
	b, err := d.Run(ctx, nil, args...)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

// CopyFiles transfers root-owned private files through stdin. The caller checks
// container ownership and supplies relative file names and an existing directory.
func (d Client) CopyFiles(ctx context.Context, container, directory string, files map[string][]byte) error {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(content))}); err != nil {
			return err
		}
		if _, err := tw.Write(content); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	_, err := d.Run(ctx, buf.Bytes(), "cp", "-", container+":"+directory)
	return err
}

type Info struct {
	Endpoint             string `json:"-"`
	OSType, Architecture string
	SecurityOptions      []string
}

func (d Client) Check(ctx context.Context) (Info, error) {
	var info Info
	host := d.Endpoint
	if host == "" {
		var contexts []struct {
			Endpoints map[string]struct{ Host string }
		}
		if err := d.JSON(ctx, &contexts, "context", "inspect"); err != nil {
			return info, err
		}
		if len(contexts) != 1 {
			return info, errors.New("select one local Docker context")
		}
		host = contexts[0].Endpoints["docker"].Host
		// Docker's environment overrides context selection during discovery only.
		if h := dockerHost(); h != "" {
			host = h
		}
	}
	if !localEndpoint(host) {
		return info, errors.New("select a local Docker socket; remote TCP/SSH Docker hosts are refused")
	}
	if err := d.JSON(ctx, &info, "--host", host, "info", "--format", "{{json .}}"); err != nil {
		return info, err
	}
	if info.OSType != "linux" || (info.Architecture != "aarch64" && info.Architecture != "arm64" && info.Architecture != "amd64" && info.Architecture != "x86_64") {
		return info, errors.New("Docker must run 64-bit Linux containers")
	}
	for _, option := range info.SecurityOptions {
		if strings.Contains(option, "rootless") {
			return info, errors.New("DeepAI Connect requires a rootful Docker engine")
		}
		if strings.Contains(option, "userns") {
			return info, errors.New("this Docker engine enforces user namespace remapping. Use a compatible local engine; deepai-connect will not bypass its isolation policy")
		}
	}
	info.Endpoint = host
	return info, nil
}

type Container struct {
	ID     string `json:"Id"`
	Config struct {
		Image  string
		Labels map[string]string
	}
	HostConfig struct{ NetworkMode string }
	State      struct {
		Running bool
		Status  string
	}
}

func (d Client) Inspect(ctx context.Context, name string) (*Container, error) {
	// A failed inspect is not proof of absence (e.g. permission denied).
	b, err := d.Run(ctx, nil, "container", "ls", "-a", "--filter", "name=^/"+name+"$", "--format", "{{.ID}}")
	if err != nil || len(bytes.TrimSpace(b)) == 0 {
		return nil, err
	}
	var cs []Container
	if err := d.JSON(ctx, &cs, "inspect", name); err != nil {
		return nil, err
	}
	if len(cs) != 1 {
		return nil, errors.New("ambiguous container identity")
	}
	return &cs[0], nil
}

// Docker's explicit context takes precedence over DOCKER_HOST during discovery.
func dockerHost() string {
	if os.Getenv("DOCKER_CONTEXT") != "" {
		return ""
	}
	return os.Getenv("DOCKER_HOST")
}
