package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"github.com/deepai-cloud/deepai-connect/internal/platform"
)

func Identity(dir string) (ed25519.PrivateKey, error) {
	k, err := LoadIdentity(dir)
	if errors.Is(err, os.ErrNotExist) {
		_, k, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return nil, e
		}
		if e = platform.WriteFile(filepath.Join(dir, "enrollment.key"), k, true); e != nil {
			return nil, e
		}
		return k, nil
	}
	return k, err
}

// LoadIdentity reads the original enrollment signer without creating a new
// identity when an enrolled machine has lost its private key.
func LoadIdentity(dir string) (ed25519.PrivateKey, error) {
	b, err := platform.ReadFile(filepath.Join(dir, "enrollment.key"))
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(b[:ed25519.SeedSize]), b) {
		return nil, errors.New("invalid local enrollment key")
	}
	return ed25519.PrivateKey(b), nil
}
func ReadInvitation(path string) (Invitation, error) {
	b, err := platform.ReadFile(path)
	if err != nil {
		return Invitation{}, err
	}
	var inv Invitation
	if json.Unmarshal(b, &inv) != nil || inv.Version != 1 || inv.ClusterID == "" || len(inv.Token) != 68 || !strings.HasPrefix(inv.Token, "dai-") || !time.Now().Before(inv.Expires) || (inv.Role != "hub" && inv.Role != "worker") || (inv.Voter && inv.Role != "hub") {
		return inv, errors.New("invalid or expired unified invitation")
	}
	return inv, ValidateURL(inv.URL)
}
func ValidateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return errors.New("enrollment URL must be an HTTPS origin")
	}
	return nil
}

// Exchange never follows redirects, writes credentials to logs, or accepts a
// cluster grant with a different device identity or overlapping address ranges.
func Exchange(ctx context.Context, inv Invitation, k ed25519.PrivateKey, node coordinator.Node, action string) (Grant, error) {
	if err := ValidateURL(inv.URL); err != nil {
		return Grant{}, err
	}
	if action != "enroll" && action != "confirm" && action != "complete" {
		return Grant{}, errors.New("invalid enrollment action")
	}
	req := Sign(Request{ClusterID: inv.ClusterID, Action: action, Node: node, Issued: time.Now().UTC()}, k)
	body, _ := json.Marshal(req)
	r, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(inv.URL, "/")+"/v1/"+action, bytes.NewReader(body))
	if err != nil {
		return Grant{}, err
	}
	r.Header.Set("Content-Type", "application/json")
	if action == "enroll" {
		r.Header.Set("Authorization", "Bearer "+inv.Token)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 50 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("enrollment redirect forbidden") }}
	resp, err := client.Do(r)
	if err != nil {
		return Grant{}, errors.New("cannot securely reach enrollment; check public HTTPS and retry with the same state")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return Grant{}, fmt.Errorf("enrollment HTTP %d; check cluster health and invitation, then resume with the same state", resp.StatusCode)
	}
	var grant Grant
	dec := json.NewDecoder(io.LimitReader(resp.Body, 4<<20))
	if dec.Decode(&grant) != nil || dec.Decode(new(any)) != io.EOF {
		return grant, errors.New("invalid enrollment response")
	}
	if err := ValidateGrant(inv, node, grant, action == "confirm"); err != nil {
		return Grant{}, err
	}
	return grant, nil
}
func ValidateGrant(inv Invitation, node coordinator.Node, g Grant, token bool) error {
	if g.Cluster.ID != inv.ClusterID || g.Cluster.URL != inv.URL || g.Role != inv.Role || g.Voter != inv.Voter || g.Self == nil || g.Self.Machine.String() != node.MachineKey || g.Self.Key.String() != node.NodeKey || len(g.Self.Addresses) != 1 || g.Self.Addresses[0].Bits() != 32 || (g.Cluster.DesiredVoters != 3 && g.Cluster.DesiredVoters != 5) {
		return errors.New("cluster grant identity mismatch")
	}
	ranges := []netip.Prefix{}
	for _, raw := range []string{g.Cluster.HostCIDR, g.Cluster.PodCIDR, g.Cluster.ServiceCIDR} {
		p, e := netip.ParsePrefix(raw)
		if e != nil || !p.Addr().Is4() || p != p.Masked() {
			return errors.New("invalid cluster ranges")
		}
		for _, other := range ranges {
			if p.Overlaps(other) {
				return errors.New("cluster ranges overlap")
			}
		}
		ranges = append(ranges, p)
	}
	if !netip.MustParsePrefix(coordinator.DefaultNetwork).Contains(ranges[0].Addr()) || !ranges[0].Contains(g.Self.Addresses[0].Addr()) || len(g.ServerURLs) == 0 {
		return errors.New("invalid cluster host network")
	}
	for _, raw := range g.ServerURLs {
		u, e := url.Parse(raw)
		if e != nil || u.Scheme != "https" || u.User != nil || u.Port() != "6443" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("invalid private Kubernetes URL")
		}
		ip, e := netip.ParseAddr(u.Hostname())
		if e != nil || !ranges[0].Contains(ip) {
			return errors.New("Kubernetes endpoint is outside host overlay")
		}
	}
	if token && !secureToken(g.Token) {
		return errors.New("K3s grant must carry a CA-pinned secure token")
	}
	return nil
}
func secureToken(s string) bool {
	if len(s) < 72 || !strings.HasPrefix(s, "K10") || s[67:69] != "::" || strings.ContainsAny(s, " \n\r\t") {
		return false
	}
	for _, c := range s[3:67] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
