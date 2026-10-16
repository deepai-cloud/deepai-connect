package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeKubernetes exercises REST paths, object metadata, optimistic concurrency,
// and Secret serialization. It deliberately returns 409 to losing creators.
type fakeKubernetes struct {
	mu       sync.Mutex
	state    *stateResource
	secret   *secretResource
	revision int
	token    string
}

func (f *fakeKubernetes) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		http.Error(w, "unauthorized", 401)
		return
	}
	switch r.URL.Path {
	case "/apis/connect.deepai.cloud/v1alpha1/namespaces/connect/networkstates/default", "/apis/connect.deepai.cloud/v1alpha1/namespaces/connect/networkstates":
		if r.Method == "GET" {
			if f.state == nil {
				http.NotFound(w, r)
				return
			}
			writeJSON(w, f.state)
			return
		}
		var state stateResource
		if err := json.NewDecoder(r.Body).Decode(&state); err != nil {
			http.Error(w, "invalid", 400)
			return
		}
		if state.APIVersion != "connect.deepai.cloud/v1alpha1" || state.Kind != "NetworkState" || state.Metadata.Name != "default" || state.Metadata.Namespace != "connect" {
			http.Error(w, "bad metadata", 400)
			return
		}
		if (r.Method == "POST" && f.state != nil) || (r.Method == "PUT" && (f.state == nil || state.Metadata.ResourceVersion != f.state.Metadata.ResourceVersion)) {
			http.Error(w, "conflict", 409)
			return
		}
		f.revision++
		state.Metadata.ResourceVersion = fmt.Sprint(f.revision)
		f.state = &state
		writeJSON(w, &state)
	case "/api/v1/namespaces/connect/secrets/connect-coordinator-keys", "/api/v1/namespaces/connect/secrets":
		if r.Method == "GET" {
			if f.secret == nil {
				http.NotFound(w, r)
				return
			}
			writeJSON(w, f.secret)
			return
		}
		if f.secret != nil {
			http.Error(w, "conflict", 409)
			return
		}
		var secret secretResource
		if err := json.NewDecoder(r.Body).Decode(&secret); err != nil {
			http.Error(w, "invalid", 400)
			return
		}
		if secret.Kind != "Secret" || secret.Type != "Opaque" || secret.Metadata.Name != "connect-coordinator-keys" {
			http.Error(w, "invalid secret", 400)
			return
		}
		f.secret = &secret
		writeJSON(w, &secret)
	default:
		http.NotFound(w, r)
	}
}

func TestKubernetesStoreCASCredentialsAndRotatingToken(t *testing.T) {
	fake := &fakeKubernetes{token: "initial"}
	httpServer := httptest.NewServer(fake)
	defer httpServer.Close()
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("initial"), 0600); err != nil {
		t.Fatal(err)
	}
	k := &KubernetesStore{BaseURL: httpServer.URL, Namespace: "connect", TokenFile: tokenPath, Client: httpServer.Client()}
	ctx := context.Background()
	first, err := k.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := k.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision != "" {
		t.Fatal("new resource has revision")
	}
	if err = k.CompareAndSwap(ctx, first, ""); err != nil {
		t.Fatal(err)
	}
	if err = k.CompareAndSwap(ctx, second, ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("create race: %v", err)
	}
	first, _ = k.Load(ctx)
	second, _ = k.Load(ctx)
	first.Domain = "first.internal"
	if err = k.CompareAndSwap(ctx, first, first.Revision); err != nil {
		t.Fatal(err)
	}
	second.Domain = "lost.internal"
	if err = k.CompareAndSwap(ctx, second, second.Revision); !errors.Is(err, ErrConflict) {
		t.Fatalf("update race: %v", err)
	}
	var wg sync.WaitGroup
	keys := make(chan Credentials, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := k.LoadOrCreateCredentials(ctx)
			if err != nil {
				t.Errorf("credentials: %v", err)
				return
			}
			keys <- c
		}()
	}
	wg.Wait()
	close(keys)
	var identity string
	for c := range keys {
		got := c.NoisePrivate.Public().String()
		if identity != "" && got != identity {
			t.Fatal("racing replicas created divergent identities")
		}
		identity = got
	}
	fake.mu.Lock()
	stateJSON, _ := json.Marshal(fake.state)
	if strings.Contains(string(stateJSON), "privkey") {
		t.Error("private credential leaked into NetworkState")
	}
	fake.token = "rotated"
	fake.mu.Unlock()
	if err = os.WriteFile(tokenPath, []byte("rotated\n"), 0600); err != nil {
		t.Fatal(err)
	}
	state, err := k.Load(ctx)
	if err != nil {
		t.Fatalf("projected token not reread: %v", err)
	}
	if state.Domain != "first.internal" {
		t.Fatal("lost successful concurrent update")
	}
}

func TestIdentityValidationAndTombstoneAllocation(t *testing.T) {
	st := NewState()
	node, _, _ := testIdentity("hub")
	if err := AllocateNode(st, &node); err != nil {
		t.Fatal(err)
	}
	original := node.Addresses[0]
	st.Nodes[node.MachineKey].Revoked = true
	next, _, _ := testIdentity("worker")
	if err := AllocateNode(st, &next); err != nil {
		t.Fatal(err)
	}
	if next.ID == node.ID || next.Addresses[0] == original {
		t.Fatal("revoked identity/address was reused")
	}
	bad, _, _ := testIdentity("client")
	bad.Addresses = node.Addresses
	if err := AllocateNode(st, &bad); err == nil {
		t.Fatal("duplicate reserved address accepted")
	}
	bad, _, _ = testIdentity("client")
	st.Network = "100.0.0.0/9"
	if err := AllocateNode(st, &bad); err == nil {
		t.Fatal("invalid overlapping host pool accepted")
	}
}
