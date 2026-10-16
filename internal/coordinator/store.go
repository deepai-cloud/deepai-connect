package coordinator

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"tailscale.com/types/key"
)

// KubernetesStore uses a namespaced NetworkState CRD and a separate Secret for
// the server private key. Resource versions provide linearizable transactions.
type KubernetesStore struct {
	BaseURL   string
	Namespace string
	Token     string
	TokenFile string
	Client    *http.Client
}

func InClusterStore(namespace string) (*KubernetesStore, error) {
	if namespace == "" {
		b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err != nil {
			return nil, err
		}
		namespace = strings.TrimSpace(string(b))
	}
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")
	if port == "" {
		port = "443"
	}
	if host == "" {
		return nil, errors.New("KUBERNETES_SERVICE_HOST is not set")
	}
	ca, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid Kubernetes CA")
	}
	return &KubernetesStore{BaseURL: "https://" + net.JoinHostPort(host, port), Namespace: namespace, TokenFile: "/var/run/secrets/kubernetes.io/serviceaccount/token", Client: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}}}, nil
}

type objectMeta struct {
	Name            string `json:"name"`
	Namespace       string `json:"namespace,omitempty"`
	ResourceVersion string `json:"resourceVersion,omitempty"`
}
type stateResource struct {
	APIVersion string     `json:"apiVersion"`
	Kind       string     `json:"kind"`
	Metadata   objectMeta `json:"metadata"`
	Spec       *State     `json:"spec"`
}
type secretResource struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   objectMeta        `json:"metadata"`
	Type       string            `json:"type"`
	Data       map[string][]byte `json:"data"`
}

func (k *KubernetesStore) api(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		if len(b) > 900<<10 {
			return errors.New("network state exceeds safe Kubernetes resource size")
		}
		body = bytes.NewReader(b)
	}
	r, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(k.BaseURL, "/")+path, body)
	if err != nil {
		return err
	}
	token := k.Token
	if k.TokenFile != "" {
		b, err := os.ReadFile(k.TokenFile)
		if err != nil {
			return err
		}
		token = strings.TrimSpace(string(b))
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("Content-Type", "application/json")
	client := k.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	res, err := client.Do(r)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusConflict {
		return ErrConflict
	}
	if res.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("Kubernetes %s %s: HTTP %d", method, path, res.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(res.Body, 2<<20)).Decode(out)
	}
	return nil
}

func (k *KubernetesStore) statePath() string {
	return "/apis/connect.deepai.cloud/v1alpha1/namespaces/" + url.PathEscape(k.Namespace) + "/networkstates"
}
func (k *KubernetesStore) secretPath() string {
	return "/api/v1/namespaces/" + url.PathEscape(k.Namespace) + "/secrets"
}

func (k *KubernetesStore) Load(ctx context.Context) (*State, error) {
	var resource stateResource
	err := k.api(ctx, "GET", k.statePath()+"/default", nil, &resource)
	if errors.Is(err, ErrNotFound) {
		return NewState(), nil
	}
	if err != nil {
		return nil, err
	}
	if resource.Spec == nil {
		return nil, errors.New("network state missing spec")
	}
	resource.Spec.Revision = resource.Metadata.ResourceVersion
	resource.Spec.normalize()
	return resource.Spec, nil
}

func (k *KubernetesStore) CompareAndSwap(ctx context.Context, state *State, expected string) error {
	resource := stateResource{APIVersion: "connect.deepai.cloud/v1alpha1", Kind: "NetworkState", Metadata: objectMeta{Name: "default", Namespace: k.Namespace, ResourceVersion: expected}, Spec: state}
	method, path := "PUT", k.statePath()+"/default"
	if expected == "" {
		method, path = "POST", k.statePath()
	}
	return k.api(ctx, method, path, &resource, nil)
}

func (k *KubernetesStore) LoadOrCreateCredentials(ctx context.Context) (Credentials, error) {
	for attempt := 0; attempt < 5; attempt++ {
		var secret secretResource
		err := k.api(ctx, "GET", k.secretPath()+"/connect-coordinator-keys", nil, &secret)
		if err == nil {
			var private key.MachinePrivate
			if err := private.UnmarshalText(secret.Data["noise-private"]); err != nil || private.IsZero() {
				return Credentials{}, errors.New("invalid coordinator Noise private key in Secret")
			}
			return Credentials{NoisePrivate: private}, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return Credentials{}, err
		}
		private := key.NewMachine()
		b, _ := private.MarshalText()
		secret = secretResource{APIVersion: "v1", Kind: "Secret", Metadata: objectMeta{Name: "connect-coordinator-keys", Namespace: k.Namespace}, Type: "Opaque", Data: map[string][]byte{"noise-private": b}}
		if err = k.api(ctx, "POST", k.secretPath(), &secret, nil); err == nil {
			return Credentials{NoisePrivate: private}, nil
		}
		if !errors.Is(err, ErrConflict) {
			return Credentials{}, err
		}
	}
	return Credentials{}, ErrConflict
}

// MemoryStore is useful for protocol tests and embedded development only.
// Production callers use KubernetesStore so restarting a pod preserves identity.
type MemoryStore struct {
	mu          sync.Mutex
	state       *State
	revision    uint64
	credentials Credentials
}

func (m *MemoryStore) Load(ctx context.Context) (*State, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == nil {
		return NewState(), nil
	}
	b, _ := json.Marshal(m.state)
	var s State
	_ = json.Unmarshal(b, &s)
	s.Revision = fmt.Sprint(m.revision)
	return &s, nil
}
func (m *MemoryStore) CompareAndSwap(ctx context.Context, s *State, expected string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	revision := ""
	if m.state != nil {
		revision = fmt.Sprint(m.revision)
	}
	if expected != revision {
		return ErrConflict
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	var copy State
	if err = json.Unmarshal(b, &copy); err != nil {
		return err
	}
	m.state = &copy
	m.revision++
	return nil
}
func (m *MemoryStore) LoadOrCreateCredentials(ctx context.Context) (Credentials, error) {
	if err := ctx.Err(); err != nil {
		return Credentials{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.credentials.NoisePrivate.IsZero() {
		m.credentials.NoisePrivate = key.NewMachine()
	}
	return m.credentials, nil
}
