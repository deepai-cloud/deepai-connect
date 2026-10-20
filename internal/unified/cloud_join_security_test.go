package unified

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/enrollment"
)

func validCloudInvitation() enrollment.Invitation {
	return enrollment.Invitation{
		Version: 1, ClusterID: "test-cluster", URL: "https://connect.example.com",
		Name: "worker-one", Role: "worker", Expires: time.Now().Add(time.Hour),
		Token: "dai-" + strings.Repeat("a", 64),
	}
}

func TestInvitationBufferBoundsEveryCopyPath(t *testing.T) {
	for _, size := range []int{(64 << 10) - 1, 64 << 10, (64 << 10) + 1, 256 << 10} {
		for _, copyPath := range []string{"write", "reader-from", "writer-to"} {
			t.Run(copyPath+"/"+strconv.Itoa(size), func(t *testing.T) {
				var b invitationBuffer
				input := bytes.Repeat([]byte("a"), size)
				var err error
				switch copyPath {
				case "write":
					_, err = b.Write(input)
				case "reader-from":
					// Hide bytes.Reader.WriteTo to exercise destination
					// ReadFrom, the optimization used for process pipes.
					_, err = io.Copy(&b, struct{ io.Reader }{bytes.NewReader(input)})
				case "writer-to":
					_, err = io.Copy(&b, bytes.NewReader(input))
				}
				if (err != nil) != (size > 64<<10) {
					t.Fatalf("size %d: error = %v", size, err)
				}
				if len(b.Bytes()) > 64<<10 {
					t.Fatalf("buffer exceeded its limit: %d", len(b.Bytes()))
				}
				if err == nil && !bytes.Equal(b.Bytes(), input) {
					t.Fatal("successful copy changed the invitation")
				}
			})
		}
	}
}

func mustJSON(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}

func TestCloudRemoteInvitationRejectsInvalidSuccessfulResponses(t *testing.T) {
	path, _ := cloudFixture(t)
	original := cloudProcess
	t.Cleanup(func() { cloudProcess = original })
	tests := []struct {
		name   string
		change func(*enrollment.Invitation)
		wire   func([]byte) []byte
	}{
		{name: "version", change: func(i *enrollment.Invitation) { i.Version = 2 }},
		{name: "missing-cluster", change: func(i *enrollment.Invitation) { i.ClusterID = "" }},
		{name: "name", change: func(i *enrollment.Invitation) { i.Name = "other-worker" }},
		{name: "role", change: func(i *enrollment.Invitation) { i.Role = "hub" }},
		{name: "voter", change: func(i *enrollment.Invitation) { i.Voter = true }},
		{name: "public-ip", change: func(i *enrollment.Invitation) { i.PublicIP = "203.0.113.20" }},
		{name: "relay", change: func(i *enrollment.Invitation) { i.RelayDomain = "other.example.com" }},
		{name: "origin", change: func(i *enrollment.Invitation) { i.URL = "https://other.example.com" }},
		{name: "expired", change: func(i *enrollment.Invitation) { i.Expires = time.Now().Add(-time.Minute) }},
		{name: "token-length", change: func(i *enrollment.Invitation) { i.Token += "a" }},
		{name: "token-prefix", change: func(i *enrollment.Invitation) { i.Token = "bad-" + strings.Repeat("a", 64) }},
		{name: "token-encoding", change: func(i *enrollment.Invitation) { i.Token = "dai-" + strings.Repeat("z", 64) }},
		{name: "unknown-field", wire: func(b []byte) []byte { return append([]byte(`{"unexpected":true,`), b[1:]...) }},
		{name: "extra-document", wire: func(b []byte) []byte { return append(b, []byte("\n{}")...) }},
		{name: "truncated", wire: func(b []byte) []byte { return b[:len(b)-1] }},
		{name: "oversized", wire: func(b []byte) []byte { return append(b, bytes.Repeat([]byte(" "), 64<<10)...) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inv := validCloudInvitation()
			if tc.change != nil {
				tc.change(&inv)
			}
			wire := mustJSON(inv)
			if tc.wire != nil {
				wire = tc.wire(wire)
			}
			cloudProcess = func(_ context.Context, _ []string, _ io.Reader, out, _ io.Writer) error {
				_, err := io.Copy(out, struct{ io.Reader }{bytes.NewReader(wire)})
				return err
			}
			dest := filepath.Join(t.TempDir(), "worker.invite")
			err := enrollCloudRemote(context.Background(), path, "worker-one", dest, defaultDir, time.Hour)
			if err == nil {
				t.Fatal("invalid successful response was accepted")
			}
			if strings.Contains(err.Error(), inv.Token) {
				t.Fatal("failure disclosed the invitation token")
			}
			if _, err := os.Lstat(dest); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid response created an invitation: %v", err)
			}
		})
	}
}

func TestCloudRemoteInvitationPreservesConcurrentPrivateOutput(t *testing.T) {
	path, _ := cloudFixture(t)
	dest := filepath.Join(t.TempDir(), "worker.invite")
	original := cloudProcess
	t.Cleanup(func() { cloudProcess = original })
	const existing = "another caller's invitation"
	cloudProcess = func(_ context.Context, _ []string, _ io.Reader, out, _ io.Writer) error {
		// A second invocation can finish while the first one is issuing an
		// invitation over SSH. The final write must still be exclusive.
		if err := os.WriteFile(dest, []byte(existing), 0600); err != nil {
			t.Fatal(err)
		}
		return json.NewEncoder(out).Encode(validCloudInvitation())
	}
	if err := enrollCloudRemote(context.Background(), path, "worker-one", dest, defaultDir, time.Hour); err == nil {
		t.Fatal("concurrent invitation was overwritten")
	}
	if raw, err := os.ReadFile(dest); err != nil || string(raw) != existing {
		t.Fatalf("private output changed: %q %v", raw, err)
	}
	entries, err := os.ReadDir(filepath.Dir(dest))
	if err != nil || len(entries) != 1 {
		t.Fatalf("failed write left temporary credentials: %v %v", entries, err)
	}
}

func TestCloudRemoteInvitationRejectsUnsafeOutputBeforeIssuing(t *testing.T) {
	path, _ := cloudFixture(t)
	original := cloudProcess
	t.Cleanup(func() { cloudProcess = original })
	cloudProcess = func(context.Context, []string, io.Reader, io.Writer, io.Writer) error {
		t.Fatal("unsafe output caused an invitation to be issued")
		return nil
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "secret")
	if err := os.WriteFile(target, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, dest := range []string{"", "-", dir, target} {
		if err := enrollCloudRemote(context.Background(), path, "worker-one", dest, defaultDir, time.Hour); err == nil {
			t.Fatalf("accepted unsafe invitation output %q", dest)
		}
	}
	for _, ttl := range []time.Duration{-time.Second, 0, 24*time.Hour + time.Second} {
		if err := enrollCloudRemote(context.Background(), path, "worker-one", filepath.Join(dir, "new"), defaultDir, ttl); err == nil {
			t.Fatalf("accepted invalid lifetime %v", ttl)
		}
	}
	if raw, err := os.ReadFile(target); err != nil || string(raw) != "preserve" {
		t.Fatalf("unsafe output changed another file: %q %v", raw, err)
	}
	t.Run("symlinks", func(t *testing.T) {
		link := filepath.Join(dir, "link")
		if err := os.Symlink(target, link); err != nil {
			if runtime.GOOS == "windows" {
				t.Skipf("symlink creation unavailable: %v", err)
			}
			t.Fatal(err)
		}
		parentLink := filepath.Join(dir, "parent-link")
		if err := os.Symlink(t.TempDir(), parentLink); err != nil {
			t.Fatal(err)
		}
		for _, dest := range []string{link, filepath.Join(parentLink, "invite")} {
			if err := enrollCloudRemote(context.Background(), path, "worker-one", dest, defaultDir, time.Hour); err == nil {
				t.Fatalf("accepted symlink invitation output %q", dest)
			}
		}
		if raw, err := os.ReadFile(target); err != nil || string(raw) != "preserve" {
			t.Fatalf("symlink output changed another file: %q %v", raw, err)
		}
	})
}

func TestNamedJoinEndpointOverridesFail(t *testing.T) {
	inv := enrollment.Invitation{Name: "hub-two", Role: "hub", PublicIP: "203.0.113.20", RelayDomain: "relay2.example.com"}
	for _, flag := range []string{"name", "public-ip", "relay-domain"} {
		t.Run(flag, func(t *testing.T) {
			name, ip, relay := inv.Name, inv.PublicIP, inv.RelayDomain
			switch flag {
			case "name":
				name = "hub-three"
			case "public-ip":
				ip = "203.0.113.30"
			case "relay-domain":
				relay = "relay3.example.com"
			}
			if err := namedJoinOptions(&inv, &name, &ip, &relay); err == nil {
				t.Fatalf("accepted a different --%s", flag)
			}
		})
	}
}
