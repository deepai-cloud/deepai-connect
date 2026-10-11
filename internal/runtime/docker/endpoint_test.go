package docker

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestPinnedCommandIgnoresRemoteEnvironment(t *testing.T) {
	for _, key := range []string{"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"} {
		t.Setenv(key, "remote-setting")
	}
	t.Setenv("DOCKER_CONFIG", "/keep/registry/credentials")
	for _, endpoint := range []string{"unix:///var/run/docker.sock", "npipe:////./pipe/docker_engine"} {
		cmd, err := Command(context.Background(), endpoint, "exec", "-i", "connect", "headscale", "users", "list")
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"--host", endpoint, "exec", "-i", "connect", "headscale", "users", "list"}
		if !reflect.DeepEqual(cmd.Args[1:], want) {
			t.Fatalf("transport escaped pinned endpoint: %v", cmd.Args)
		}
		keptConfig := false
		for _, value := range cmd.Env {
			key, _, _ := strings.Cut(value, "=")
			switch strings.ToUpper(key) {
			case "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH":
				t.Fatalf("transport inherited override %s", key)
			case "DOCKER_CONFIG":
				keptConfig = true
			}
		}
		if !keptConfig {
			t.Fatal("registry credential configuration was removed")
		}
	}
}

func TestCheckPinsInfoBeforeContextCanDrift(t *testing.T) {
	t.Setenv("DOCKER_HOST", "")
	t.Setenv("DOCKER_CONTEXT", "")
	calls := 0
	d := Client{Run: func(_ context.Context, _ []byte, args ...string) ([]byte, error) {
		calls++
		if calls == 1 {
			if !reflect.DeepEqual(args, []string{"context", "inspect"}) {
				t.Fatalf("unexpected discovery: %v", args)
			}
			// The user changes Docker's current context after this response.
			return []byte(`[{"Endpoints":{"docker":{"Host":"unix:///verified.sock"}}}]`), nil
		}
		if !reflect.DeepEqual(args, []string{"--host", "unix:///verified.sock", "info", "--format", "{{json .}}"}) {
			t.Fatalf("info followed changed current context: %v", args)
		}
		return []byte(`{"OSType":"linux","Architecture":"amd64"}`), nil
	}}
	info, err := d.Check(context.Background())
	if err != nil || info.Endpoint != "unix:///verified.sock" || calls != 2 {
		t.Fatalf("bad endpoint selection: %+v %v %d", info, err, calls)
	}
	d.Endpoint = info.Endpoint
	t.Setenv("DOCKER_HOST", "ssh://remote.example")
	t.Setenv("DOCKER_CONTEXT", "remote")
	if _, err := d.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatal("pinned checks rediscovered a changed context")
	}
}

func TestPinnedEndpointCannotBeReplaced(t *testing.T) {
	for _, target := range []string{"ssh://remote", "tcp://127.0.0.1:2375", ""} {
		if _, err := LocalRunner(target)(context.Background(), nil, "info"); err == nil {
			t.Fatalf("accepted %q", target)
		}
	}
	if _, err := Command(context.Background(), "unix:///verified.sock", "--host", "unix:///other.sock", "info"); err == nil {
		t.Fatal("pinned endpoint replaced by command arguments")
	}

}
