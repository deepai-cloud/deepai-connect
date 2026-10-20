package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestEnrollmentIdentityPersistsAndRejectsCorruption(t *testing.T) {
	dir := t.TempDir()
	first, err := Identity(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Identity(dir)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("resume changed signing identity")
	}
	path := filepath.Join(dir, "enrollment.key")
	fi, err := os.Stat(path)
	if err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0600) {
		t.Fatal("enrollment key is not private")
	}
	bad := append([]byte{}, first...)
	bad[len(bad)-1] ^= 1
	if err = os.WriteFile(path, bad, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Identity(dir); err == nil {
		t.Fatal("corrupted private identity accepted")
	}
}
func TestGrantValidationRejectsWrongClusterIdentityRoutesAndToken(t *testing.T) {
	b, _, _ := fixture(t)
	req, g, inv := enrollOne(t, b, "worker", false)
	if err := ValidateGrant(inv, req.Node, g, false); err != nil {
		t.Fatal(err)
	}
	changes := []struct {
		name   string
		change func(*Grant)
	}{{"cluster", func(g *Grant) { g.Cluster.ID = "other" }}, {"voter", func(g *Grant) { g.Voter = true }}, {"role", func(g *Grant) { g.Role = "hub" }}, {"overlap", func(g *Grant) { g.Cluster.PodCIDR = g.Cluster.HostCIDR }}, {"public-api", func(g *Grant) { g.ServerURLs = []string{"https://203.0.113.1:6443"} }}, {"api-user", func(g *Grant) { g.ServerURLs = []string{"https://user:password@100.64.0.1:6443"} }}, {"api-path", func(g *Grant) { g.ServerURLs = []string{"https://100.64.0.1:6443/private"} }}, {"even-voters", func(g *Grant) { g.Cluster.DesiredVoters = 4 }}, {"foreign-address", func(g *Grant) {
		copy := *g.Self
		copy.Addresses = []netip.Prefix{netip.MustParsePrefix("192.0.2.2/32")}
		g.Self = &copy
	}}}
	for _, test := range changes {
		t.Run(test.name, func(t *testing.T) {
			copy := g
			test.change(&copy)
			if err := ValidateGrant(inv, req.Node, copy, false); err == nil {
				t.Fatal("invalid remote grant accepted")
			}
		})
	}
	if err := ValidateGrant(inv, req.Node, g, true); err == nil {
		t.Fatal("confirmation accepted without CA-pinned token")
	}
	g.Token = "K10" + strings.Repeat("a", 64) + "::abcdef.0123456789abcdef"
	if err := ValidateGrant(inv, req.Node, g, true); err != nil {
		t.Fatal(err)
	}
}
func TestProbeHandlerSignsFreshDomainSeparatedChallenge(t *testing.T) {
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	challenge := make([]byte, 32)
	_, _ = rand.Read(challenge)
	r := httptest.NewRequest("GET", "/probe?challenge="+base64.RawURLEncoding.EncodeToString(challenge), nil)
	w := httptest.NewRecorder()
	ProbeHandler(private).ServeHTTP(w, r)
	if w.Code != http.StatusOK || !ed25519.Verify(pub, append([]byte("deepai-connect-overlay-probe-v1:"), challenge...), w.Body.Bytes()) {
		t.Fatal("probe did not prove device identity")
	}
	if ed25519.Verify(pub, challenge, w.Body.Bytes()) {
		t.Fatal("probe signature can be repurposed outside its protocol")
	}
	bad := httptest.NewRecorder()
	ProbeHandler(private).ServeHTTP(bad, httptest.NewRequest("GET", "/probe?challenge=short", nil))
	if bad.Code != 400 {
		t.Fatal("accepted malformed probe challenge")
	}
}
func TestExpiredInvitationCannotCreateMembership(t *testing.T) {
	b, srv, _ := fixture(t)
	inv, _ := b.Invite(context.Background(), "worker", false, time.Hour)
	if err := srv.Update(context.Background(), func(s *coordinator.State) error {
		r, err := ReadRegistry(s)
		if err != nil {
			return err
		}
		r.Invites[coordinator.TokenHash(inv.Token)].Expires = time.Now().Add(-time.Second)
		return WriteRegistry(s, r)
	}); err != nil {
		t.Fatal(err)
	}
	n, k := identity("late-worker")
	if _, err := b.enroll(context.Background(), request(n, k, "enroll"), inv.Token); err == nil {
		t.Fatal("expired invitation accepted")
	}
}
