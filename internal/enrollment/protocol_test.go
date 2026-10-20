package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/cloudconfig"
	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
)

// Preserve the public invitation origin while connecting only to the fixture.
// TLS still verifies the test server certificate against its explicit test CA.
func enrollmentTLSTransport(t *testing.T, server *httptest.Server) *http.Transport {
	t.Helper()
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.ServerName = "127.0.0.1"
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	return transport
}

func TestNamedEnrollmentAndConfigurationOverTLS(t *testing.T) {
	for _, name := range []string{"my-worker", "hub-second"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			b, srv, backend := fixture(t)
			spec := declaredCloud()
			spec.Bootstrap.TLSCertFile = "/private/administrator/cert.pem"
			spec.Bootstrap.TLSKeyFile = "/private/administrator/key.pem"
			applyDeclaredCloud(t, b, spec, nil)
			inv, err := b.InviteNode(ctx, name, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			type observedRequest struct{ action, bearer string }
			observed := make(chan observedRequest, 16)
			handler := b.Handler()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				observed <- observedRequest{r.URL.Path, r.Header.Get("Authorization")}
				handler.ServeHTTP(w, r)
			}))
			defer server.Close()
			transport := enrollmentTLSTransport(t, server)
			node, signer := identity(name)
			node.Endpoints = nil // Workers behind NAT do not need inbound access.
			if inv.Role == "hub" {
				node.Endpoints = []netip.AddrPort{netip.MustParseAddrPort(inv.PublicIP + ":41641")}
			}
			// Signed client input is still untrusted: role and routing authority
			// come from the invitation and trusted Kubernetes allocation.
			node.Role = "hub"
			node.Addresses = []netip.Prefix{netip.MustParsePrefix("100.100.100.100/32")}
			node.ApprovedRoutes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
			node.PodRoutes = []netip.Prefix{netip.MustParsePrefix("10.42.255.0/24")}
			initial, err := exchange(ctx, inv, signer, node, "enroll", transport)
			if err != nil {
				t.Fatal(err)
			}
			if initial.Token != "" || initial.Role != inv.Role || backend.tokens.Load() != 0 {
				t.Fatal("enrollment released credentials or trusted a client-supplied role")
			}
			state, err := b.Store.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			persisted := state.Nodes[node.MachineKey]
			if len(persisted.ApprovedRoutes) != 0 || len(persisted.PodRoutes) != 0 || reflect.DeepEqual(persisted.Addresses, node.Addresses) {
				t.Fatal("enrollment trusted client-supplied addresses or route approvals")
			}
			confirmed, err := exchange(ctx, inv, signer, node, "confirm", transport)
			if err != nil || !secureToken(confirmed.Token) || backend.tokens.Load() != 1 {
				t.Fatalf("connectivity confirmation did not release one secure credential: %v", err)
			}
			if (backend.serverTokens.Load() == 1) != (inv.Role == "hub") {
				t.Fatal("credential privilege did not match invited role")
			}
			completed, err := exchange(ctx, inv, signer, node, "complete", transport)
			if err != nil || completed.Token != "" {
				t.Fatalf("completion failed or released credentials: %v", err)
			}
			// Delete all bearer capabilities and make Kubernetes unavailable.
			// Persisted identity must remain sufficient for configuration pulls.
			if err := srv.Update(ctx, func(s *coordinator.State) error {
				registry, err := ReadRegistry(s)
				if err != nil {
					return err
				}
				registry.Invites = map[string]*Invite{}
				return WriteRegistry(s, registry)
			}); err != nil {
				t.Fatal(err)
			}
			desired := spec.Nodes[name]
			desired.Labels = map[string]string{"location": "new-site"}
			spec.Nodes[name] = desired
			revision := applyDeclaredCloud(t, b, spec, nil)
			backend.healthy = func() error { return errors.New("Kubernetes offline") }
			backend.probe = func() error { return errors.New("overlay unavailable") }
			inv.Token = ""
			inv.Expires = time.Now().Add(-time.Hour)
			configuration, err := exchange(ctx, inv, signer, node, "config", transport)
			if err != nil {
				t.Fatal(err)
			}
			if configuration.Token != "" || backend.tokens.Load() != 1 || configuration.Configuration.Revision != revision ||
				configuration.Configuration.Node.Labels["location"] != "new-site" ||
				configuration.Self.ID != initial.Self.ID || !reflect.DeepEqual(configuration.Self.Addresses, initial.Self.Addresses) {
				t.Fatal("configuration pull lost identity, returned stale state or released credentials")
			}
			wire, err := json.Marshal(configuration)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"root@", "/private/administrator", confirmed.Token} {
				if bytes.Contains(wire, []byte(secret)) {
					t.Fatalf("configuration disclosed administrative material %q", secret)
				}
			}
			for index, action := range []string{"enroll", "confirm", "complete", "config"} {
				request := <-observed
				if request.action != "/v1/"+action || (request.bearer != "") != (index == 0) {
					t.Fatalf("unexpected authentication on %s: %+v", action, request)
				}
			}
			if err := srv.Update(ctx, func(s *coordinator.State) error { s.Nodes[node.MachineKey].Revoked = true; return nil }); err != nil {
				t.Fatal(err)
			}
			if _, err := exchange(ctx, inv, signer, node, "config", transport); err == nil {
				t.Fatal("revoked member fetched configuration over HTTPS")
			}
		})
	}
}

func TestEnrollmentHandlerRejectsMalformedWireRequestsWithoutMutation(t *testing.T) {
	b, _, backend := fixture(t)
	ctx := context.Background()
	applyDeclaredCloud(t, b, declaredCloud(), nil)
	inv, err := b.InviteNode(ctx, "my-worker", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	node, signer := identity("my-worker")
	request := request(node, signer, "enroll")
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	signedBody := func(alter func(*Request), signing bool) []byte {
		copy := request
		alter(&copy)
		if signing {
			copy = Sign(copy, signer)
		}
		raw, err := json.Marshal(copy)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	tests := []struct {
		name, method, path, bearer string
		body                       []byte
		status                     int
	}{
		{"get", "GET", "/v1/enroll", "Bearer " + inv.Token, body, 405},
		{"no-bearer", "POST", "/v1/enroll", "", body, 403},
		{"wrong-bearer", "POST", "/v1/enroll", "Bearer dai-" + strings.Repeat("0", 64), body, 403},
		{"unknown-field", "POST", "/v1/enroll", "Bearer " + inv.Token, append([]byte(`{"unknown":true,`), body[1:]...), 400},
		{"nested-unknown", "POST", "/v1/enroll", "Bearer " + inv.Token, []byte(strings.Replace(string(body), `"node":{`, `"node":{"unknown":true,`, 1)), 400},
		{"trailing-object", "POST", "/v1/enroll", "Bearer " + inv.Token, append(append([]byte{}, body...), []byte(`{}`)...), 400},
		{"null", "POST", "/v1/enroll", "Bearer " + inv.Token, []byte("null"), 400},
		{"oversized", "POST", "/v1/enroll", "Bearer " + inv.Token, append(append([]byte{}, body...), bytes.Repeat([]byte(" "), 64<<10)...), 400},
		{"short-signature", "POST", "/v1/enroll", "Bearer " + inv.Token, signedBody(func(r *Request) { r.Signature = r.Signature[:10] }, false), 400},
		{"short-key", "POST", "/v1/enroll", "Bearer " + inv.Token, signedBody(func(r *Request) { r.PublicKey = r.PublicKey[:10] }, false), 400},
		{"tampered-name", "POST", "/v1/enroll", "Bearer " + inv.Token, signedBody(func(r *Request) { r.Node.Hostname = "different" }, false), 400},
		{"tampered-action", "POST", "/v1/confirm", "Bearer " + inv.Token, signedBody(func(r *Request) { r.Action = "confirm" }, false), 400},
		{"wrong-cluster", "POST", "/v1/enroll", "Bearer " + inv.Token, signedBody(func(r *Request) { r.ClusterID = "foreign-cluster" }, true), 403},
		{"wrong-name", "POST", "/v1/enroll", "Bearer " + inv.Token, signedBody(func(r *Request) { r.Node.Hostname = "undeclared" }, true), 403},
		{"expired", "POST", "/v1/enroll", "Bearer " + inv.Token, signedBody(func(r *Request) { r.Issued = time.Now().Add(-10 * time.Minute) }, true), 400},
		{"future", "POST", "/v1/enroll", "Bearer " + inv.Token, signedBody(func(r *Request) { r.Issued = time.Now().Add(10 * time.Minute) }, true), 400},
		{"path-action-mismatch", "POST", "/v1/config", "Bearer " + inv.Token, body, 404},
		{"unknown-action", "POST", "/v1/delete", "Bearer " + inv.Token, signedBody(func(r *Request) { r.Action = "delete" }, true), 404},
	}
	before, err := b.Store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(b.Handler())
	defer server.Close()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req, err := http.NewRequest(test.method, server.URL+test.path, bytes.NewReader(test.body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", test.bearer)
			response, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != test.status || response.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("got HTTP %d headers=%v body=%s; want %d", response.StatusCode, response.Header, raw, test.status)
			}
			if bytes.Contains(raw, []byte(inv.Token)) {
				t.Fatal("denial response disclosed the invitation")
			}
			after, err := b.Store.Load(ctx)
			if err != nil || !reflect.DeepEqual(before, after) || backend.tokens.Load() != 0 {
				t.Fatalf("invalid wire request changed durable state or released credentials: %v", err)
			}
		})
	}
}

func TestExchangeRefusesRedirectsWithoutForwardingCredentials(t *testing.T) {
	b, _, _ := fixture(t)
	req, grant, inv := enrollOne(t, b, "worker", false)
	var destinationCalls atomic.Int32
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		destinationCalls.Add(1)
		_ = json.NewEncoder(w).Encode(grant)
	}))
	defer destination.Close()
	_, signer, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []int{301, 302, 303, 307, 308} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, destination.URL+"/v1/enroll", status)
		}))
		transport := server.Client().Transport
		copy := inv
		copy.URL = server.URL
		for _, action := range []string{"enroll", "config"} {
			_, err := exchange(context.Background(), copy, signer, req.Node, action, transport)
			if err == nil || strings.Contains(err.Error(), inv.Token) {
				t.Fatalf("redirect status %d action %s was accepted or disclosed credentials: %v", status, action, err)
			}
		}
		server.Close()
	}
	if destinationCalls.Load() != 0 {
		t.Fatal("redirect target received an enrollment request")
	}
}

func TestExchangeRejectsUntrustedTLSBeforeSendingInvitation(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1) }))
	defer server.Close()
	node, signer := identity("test-worker")
	inv := Invitation{URL: server.URL, ClusterID: "cluster-id", Token: "dai-" + strings.Repeat("a", 64)}
	if _, err := Exchange(context.Background(), inv, signer, node, "enroll"); err == nil {
		t.Fatal("public Exchange accepted an untrusted test CA")
	}
	if received.Load() != 0 {
		t.Fatal("invitation was sent before verifying the TLS server")
	}
}

func TestConfigExchangeRejectsInvalidResponses(t *testing.T) {
	b, _, _ := fixture(t)
	applyDeclaredCloud(t, b, declaredCloud(), nil)
	inv, err := b.InviteNode(context.Background(), "my-worker", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	node, signer := identity("my-worker")
	grant, err := b.enroll(context.Background(), request(node, signer, "enroll"), inv.Token)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("exact-size-limit", func(t *testing.T) {
		raw := append(append([]byte{}, valid...), bytes.Repeat([]byte(" "), (4<<20)-len(valid))...)
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(raw)
		}))
		defer server.Close()
		if _, err := exchange(context.Background(), inv, signer, node, "config", enrollmentTLSTransport(t, server)); err != nil {
			t.Fatalf("valid configuration at response size limit was rejected: %v", err)
		}
	})
	for _, test := range []struct {
		name    string
		alter   func(*Grant)
		rewrite func([]byte) []byte
	}{
		{name: "credentials", alter: func(g *Grant) { g.Token = "K10" + strings.Repeat("a", 64) + "::server:private" }},
		{name: "credentials-in-invalid-response", alter: func(g *Grant) { g.Token = "K10" + strings.Repeat("a", 64) + "::server:private" }, rewrite: func(raw []byte) []byte { return append(raw, []byte(`{}`)...) }},
		{name: "another-node", alter: func(g *Grant) { g.Configuration.Name = "hub-initial" }},
		{name: "administrative-ssh", alter: func(g *Grant) { g.Configuration.Node.Connection = cloudconfig.Connection{SSH: "root@203.0.113.10"} }},
		{name: "missing-configuration", alter: func(g *Grant) { g.Configuration = nil }},
		{name: "wrong-node-key", alter: func(g *Grant) { g.Self.Key = g.Peers[0].Key }},
		{name: "wrong-cluster", alter: func(g *Grant) { g.Cluster.ID = "other-cluster" }},
		{name: "trailing-json", rewrite: func(raw []byte) []byte { return append(raw, []byte(`{}`)...) }},
		{name: "truncated-json", rewrite: func(raw []byte) []byte { return raw[:len(raw)-1] }},
		{name: "oversized", rewrite: func(raw []byte) []byte {
			return append(raw, bytes.Repeat([]byte(" "), (4<<20)+1-len(raw))...)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var changed Grant
			if err := json.Unmarshal(valid, &changed); err != nil {
				t.Fatal(err)
			}
			if test.alter != nil {
				test.alter(&changed)
			}
			raw, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			if test.rewrite != nil {
				raw = test.rewrite(raw)
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(raw)
			}))
			defer server.Close()
			result, err := exchange(context.Background(), inv, signer, node, "config", enrollmentTLSTransport(t, server))
			if err == nil {
				t.Fatal("accepted invalid remote configuration response")
			}
			if !reflect.DeepEqual(result, Grant{}) || strings.Contains(err.Error(), changed.Token) && changed.Token != "" {
				t.Fatal("failed configuration exchange returned unvalidated state or logged credentials")
			}
		})
	}
}
