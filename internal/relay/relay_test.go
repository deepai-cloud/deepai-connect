package relay

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPersistentRelayIdentityDoesNotRotateOnResumeOrCorruption(t *testing.T) {
	dir := t.TempDir()
	first, err := loadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := loadIdentity(dir)
	if err != nil || first.Public() != again.Public() {
		t.Fatal("relay identity rotated", err)
	}
	path := filepath.Join(dir, "derp.key")
	if err = os.WriteFile(path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = loadIdentity(dir); err == nil {
		t.Fatal("corrupt identity silently replaced")
	}
}
func TestRelayRefusesUnauthenticatedRemoteAdmissionAndPublicPlaintext(t *testing.T) {
	for _, c := range []Config{{VerifyURL: "http://control.example.com/verify"}, {VerifyURL: "https://control.example.com/verify", StateDir: t.TempDir(), Listen: "0.0.0.0:3340"}} {
		if err := Run(context.Background(), c); err == nil {
			t.Fatal("insecure relay configuration accepted")
		}
	}
}
