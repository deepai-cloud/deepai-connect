package docker

import (
	"context"
	"errors"
	"testing"
)

func TestAdversarialDockerContextOverridesHost(t *testing.T) {
	t.Setenv("DOCKER_CONTEXT", "remote")
	t.Setenv("DOCKER_HOST", "unix:///local.sock")
	d := Client{Run: func(_ context.Context, _ []byte, args ...string) ([]byte, error) {
		if args[0] != "context" {
			t.Fatalf("remote engine was contacted: %v", args)
		}
		return []byte(`[{"Endpoints":{"docker":{"Host":"ssh://remote.example"}}}]`), nil
	}}
	if _, err := d.Check(context.Background()); err == nil {
		t.Fatal("remote context accepted despite DOCKER_CONTEXT precedence")
	}
}

func TestAdversarialInspectFailureIsNotAbsence(t *testing.T) {
	denied := errors.New("permission denied")
	d := Client{Run: func(context.Context, []byte, ...string) ([]byte, error) { return nil, denied }}
	if _, err := d.Inspect(context.Background(), "existing"); !errors.Is(err, denied) {
		t.Fatal("lost inspection error", err)
	}
}

func TestAdversarialOutputLimit(t *testing.T) {
	var b limitedBuffer
	if _, err := b.Write(make([]byte, 8<<20)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte{1}); err == nil {
		t.Fatal("unbounded Docker output accepted")
	}
}
