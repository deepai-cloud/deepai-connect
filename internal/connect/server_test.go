package connect

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/contract/edgeaccess"
	"github.com/deepai-cloud/deepai-connect/internal/platform"
	"github.com/deepai-cloud/deepai-connect/internal/runtime/docker"
)

func fixture(t *testing.T) *Server {
	t.Helper()
	s := State{ID: random(), Domain: "mesh.deepai.test", PublicIP: "8.8.8.8", Email: "owner@example.com", Apps: []string{"app.deepai.test"}, Token: random(), Containers: map[string]string{}, Configured: map[string]bool{}}
	var err error
	s.CA, s.Certificate, s.Key, err = certificates(s.Domain)
	if err != nil {
		t.Fatal(err)
	}
	return &Server{State: s, Dir: t.TempDir()}
}

func TestCredentialTrustAndValidation(t *testing.T) {
	h := fixture(t)
	a := edgeaccess.Profile{Version: 1, Server: h.Domain, Port: 7000, Token: h.Token, CA: h.CA, Domains: h.Apps}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair([]byte(h.Certificate), []byte(h.Key))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(h.CA))
	if _, err = cert.Verify(x509.VerifyOptions{DNSName: h.Domain, Roots: roots}); err != nil {
		t.Fatal(err)
	}
	if _, err = cert.Verify(x509.VerifyOptions{DNSName: "attacker.example.com", Roots: roots}); err == nil {
		t.Fatal("wrong server name accepted")
	}
	for _, mutate := range []func(*edgeaccess.Profile){func(a *edgeaccess.Profile) { a.Token = "short" }, func(a *edgeaccess.Profile) { a.CA = h.Certificate }, func(a *edgeaccess.Profile) { a.Domains = []string{"*.example.com"} }, func(a *edgeaccess.Profile) { a.Domains = []string{a.Server} }, func(a *edgeaccess.Profile) { a.Port = 443 }, func(a *edgeaccess.Profile) { a.Server = "127.0.0.1" }} {
		copy := a
		mutate(&copy)
		if copy.Validate() == nil {
			t.Fatal("invalid credential accepted")
		}
	}
	path := filepath.Join(t.TempDir(), "access.json")
	if err = platform.WriteFile(path, encoded(a), true); err != nil {
		t.Fatal(err)
	}
	if _, err = edgeaccess.Read(path); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err = os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err = edgeaccess.Read(path); err == nil {
			t.Fatal("accepted publicly readable publishing credential")
		}
	}
}

func TestExpiredCredentialsCanStillIdentifyPublisher(t *testing.T) {
	h := fixture(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	a := edgeaccess.Profile{Version: 1, Server: h.Domain, Port: 7000, Token: h.Token, CA: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), Domains: h.Apps}
	if err = a.ValidateIdentity(); err != nil {
		t.Fatal("expiry prevents publisher cleanup", err)
	}
	if a.Validate() == nil {
		t.Fatal("expired trust accepted for new connection")
	}
}

func TestGeneratedConfigBoundaries(t *testing.T) {
	h := fixture(t)
	var hs map[string]any
	if err := json.Unmarshal(headscaleConfig(h.State), &hs); err != nil {
		t.Fatal(err)
	}
	derp := hs["derp"].(map[string]any)
	if len(derp["urls"].([]any)) != 0 || derp["server"].(map[string]any)["verify_clients"] != true {
		t.Fatal("relay escapes ownership")
	}
	var f map[string]any
	if err := json.Unmarshal(frpsConfig(h.State), &f); err != nil {
		t.Fatal(err)
	}
	if f["transport"].(map[string]any)["tls"].(map[string]any)["force"] != true || f["webServer"] != nil {
		t.Fatal("insecure FRP listener")
	}
	if strings.Contains(string(caddyConfig(h.State)), "on_demand") || strings.Contains(string(caddyConfig(h.State)), "*") {
		t.Fatal("unbounded certificate issuance")
	}
}

func TestNetworkOnlyConfiguration(t *testing.T) {
	h := fixture(t)
	h.Apps = nil
	if err := validConfig(h.State); err != nil {
		t.Fatal("network-only server configuration rejected", err)
	}
	var c map[string]any
	if err := json.Unmarshal(caddyConfig(h.State), &c); err != nil {
		t.Fatal(err)
	}
	apps := c["apps"].(map[string]any)
	routes := apps["http"].(map[string]any)["servers"].(map[string]any)["edge"].(map[string]any)["routes"].([]any)
	policies := apps["tls"].(map[string]any)["automation"].(map[string]any)["policies"].([]any)
	if len(routes) != 1 || !reflect.DeepEqual(policies[0].(map[string]any)["subjects"], []any{h.Domain}) {
		t.Fatal("network-only server must expose only its coordination hostname")
	}
}

func TestExistingResourceFailuresBlockCreation(t *testing.T) {
	ctx := context.Background()
	d := docker.Client{Run: func(context.Context, []byte, ...string) ([]byte, error) { return []byte("orphan"), nil }}
	if checkFresh(ctx, d) == nil {
		t.Fatal("orphan resources accepted")
	}
	d.Run = func(context.Context, []byte, ...string) ([]byte, error) { return nil, errors.New("daemon unavailable") }
	if checkFresh(ctx, d) == nil {
		t.Fatal("inspection failure treated as absence")
	}
	h := fixture(t)
	h.Containers["headscale"] = strings.Repeat("a", 64)
	h.Docker.Run = func(context.Context, []byte, ...string) ([]byte, error) { return nil, nil }
	if h.verify(ctx) == nil {
		t.Fatal("missing saved identity accepted")
	}
}

func TestForeignResourcesAndReplacedContainerRefused(t *testing.T) {
	h := fixture(t)
	h.Containers["headscale"] = strings.Repeat("a", 64)
	h.Docker.Run = func(_ context.Context, _ []byte, args ...string) ([]byte, error) {
		if args[0] == "container" {
			return []byte("present"), nil
		}
		if args[0] == "inspect" {
			return []byte(`[{"Id":"` + strings.Repeat("b", 64) + `","Config":{"Labels":{"cloud.deepai.connect":"` + h.ID + `","cloud.deepai.connect.service":"headscale"}},"HostConfig":{"NetworkMode":"` + h.name("network") + `"}}]`), nil
		}
		return nil, errors.New("unexpected mutation")
	}
	if h.verify(context.Background()) == nil {
		t.Fatal("replacement accepted")
	}
	h.Docker.Run = func(_ context.Context, _ []byte, args ...string) ([]byte, error) {
		if args[1] == "ls" {
			return []byte(h.name("data")), nil
		}
		if args[1] == "inspect" {
			return []byte(`[{"Labels":{"cloud.deepai.connect":"foreign"}}]`), nil
		}
		t.Fatal("mutated foreign resource")
		return nil, nil
	}
	if _, err := h.resource(context.Background(), "volume", "data"); err == nil {
		t.Fatal("foreign volume accepted")
	}
}

func TestInvalidSavedStateAndCLI(t *testing.T) {
	if err := Run(context.Background(), []string{"up", "--help"}); err != nil {
		t.Fatal(err)
	}
	h := fixture(t)
	if err := h.save(); err != nil {
		t.Fatal(err)
	}
	if _, err := load(h.Dir, docker.Client{}); err != nil {
		t.Fatal(err)
	}
	h.ID = "short"
	if err := h.save(); err != nil {
		t.Fatal(err)
	}
	if _, err := load(h.Dir, docker.Client{}); err == nil {
		t.Fatal("unsafe identity accepted")
	}
	for _, args := range [][]string{{"status", "--domain", "mesh.example.com"}, {"invite"}, {"access"}, {"status", "--out", "x"}, {"up", "--out", "x"}, {"destroy"}} {
		if Run(context.Background(), args) == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestInviteDoesNotOverwrite(t *testing.T) {
	h := fixture(t)
	out := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(out, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	h.Docker.Run = func(context.Context, []byte, ...string) ([]byte, error) {
		t.Fatal("issued key before output collision check")
		return nil, nil
	}
	if h.invite(context.Background(), out) == nil {
		t.Fatal("overwrote credential")
	}
}

func TestInviteUsesOwnerAndOneHourSingleUseCredential(t *testing.T) {
	for _, ownerID := range []string{`42`, `"42"`} {
		t.Run(ownerID, func(t *testing.T) {
			h := fixture(t)
			h.Containers["headscale"] = strings.Repeat("a", 64)
			key := strings.Repeat("b", 48)
			calls := 0
			h.Docker.Run = func(_ context.Context, input []byte, args ...string) ([]byte, error) {
				calls++
				prefix := []string{"exec", h.Containers["headscale"], "/ko-app/headscale", "--config", "/etc/headscale/config.json", "--output", "json"}
				if len(input) != 0 || len(args) < len(prefix) || !reflect.DeepEqual(args[:len(prefix)], prefix) {
					t.Fatalf("unexpected Headscale invocation: %v", args)
				}
				command := args[len(prefix):]
				switch calls {
				case 1:
					if !reflect.DeepEqual(command, []string{"users", "list", "--name", "owner"}) {
						t.Fatalf("wrong owner lookup: %v", command)
					}
					return []byte(`[{"id":` + ownerID + `,"name":"owner"}]`), nil
				case 2:
					// Absence of --reusable and --ephemeral keeps this a one-use
					// invitation for a durable, independently managed network peer.
					if !reflect.DeepEqual(command, []string{"preauthkeys", "create", "--user", "42", "--expiration", "1h"}) {
						t.Fatalf("wrong invitation scope or lifetime: %v", command)
					}
					return []byte(`{"key":"` + key + `"}`), nil
				default:
					t.Fatal("unexpected Headscale mutation")
					return nil, nil
				}
			}
			out := filepath.Join(t.TempDir(), "network.key")
			if err := h.invite(context.Background(), out); err != nil {
				t.Fatal(err)
			}
			data, err := platform.ReadFile(out)
			if err != nil || string(data) != key+"\n" || calls != 2 {
				t.Fatal("invitation was not exported exactly once", err)
			}
			if runtime.GOOS != "windows" {
				info, err := os.Stat(out)
				if err != nil || info.Mode().Perm() != 0600 {
					t.Fatal("invitation is not private", err)
				}
			}
		})
	}
}

func TestInviteRejectsAmbiguousOrInvalidOwnerBeforeIssuingKey(t *testing.T) {
	for _, response := range []string{
		`[{"id":1,"name":"foreign"}]`,
		`[{"id":1,"name":"owner"},{"id":2,"name":"owner"}]`,
		`[{"id":0,"name":"owner"}]`,
		`[{"id":"--help","name":"owner"}]`,
		`not-json`,
	} {
		t.Run(response, func(t *testing.T) {
			h := fixture(t)
			calls := 0
			h.Docker.Run = func(context.Context, []byte, ...string) ([]byte, error) {
				calls++
				if calls != 1 {
					t.Fatal("issued a credential for invalid owner")
				}
				return []byte(response), nil
			}
			out := filepath.Join(t.TempDir(), "network.key")
			if h.invite(context.Background(), out) == nil {
				t.Fatal("accepted invalid owner")
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatal("exported invalid owner's credential")
			}
		})
	}
}
