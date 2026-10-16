package unified

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/cluster"
	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"github.com/deepai-cloud/deepai-connect/internal/enrollment"
)

type kube struct{ store *coordinator.KubernetesStore }
type kubeError struct {
	Status       int
	Method, Path string
}

func (e *kubeError) Error() string {
	return fmt.Sprintf("Kubernetes %s %s: HTTP %d", e.Method, e.Path, e.Status)
}

func (k kube) call(ctx context.Context, method, path string, in, out any) error {
	var body []byte
	var err error
	if in != nil {
		body, err = json.Marshal(in)
		if err != nil {
			return err
		}
	}
	r, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(k.store.BaseURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	token := k.store.Token
	if k.store.TokenFile != "" {
		b, e := os.ReadFile(k.store.TokenFile)
		if e != nil {
			return e
		}
		token = strings.TrimSpace(string(b))
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("Content-Type", "application/json")
	resp, err := k.store.Client.Do(r)
	if err != nil {
		return errors.New("Kubernetes API unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &kubeError{Status: resp.StatusCode, Method: method, Path: path}
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out)
	}
	_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return err
}

func localKube(ctx context.Context, m *cluster.Manager) (kube, error) {
	data, err := m.Runner.Run(ctx, nil, m.Config.K3sBinary, "kubectl", "--kubeconfig", filepath.Join(m.Config.DataDir, "kubeconfig"), "config", "view", "--raw", "--minify", "-o", "json")
	if err != nil {
		return kube{}, err
	}
	var cfg struct {
		Clusters []struct {
			Cluster struct {
				Server string `json:"server"`
				CA     string `json:"certificate-authority-data"`
			} `json:"cluster"`
		} `json:"clusters"`
		Users []struct {
			User struct {
				Cert  string `json:"client-certificate-data"`
				Key   string `json:"client-key-data"`
				Token string `json:"token"`
			} `json:"user"`
		} `json:"users"`
	}
	if json.Unmarshal(data, &cfg) != nil || len(cfg.Clusters) != 1 || len(cfg.Users) != 1 {
		return kube{}, errors.New("invalid K3s admin kubeconfig")
	}
	ca, e := base64.StdEncoding.DecodeString(cfg.Clusters[0].Cluster.CA)
	if e != nil {
		return kube{}, e
	}
	cert, e := base64.StdEncoding.DecodeString(cfg.Users[0].User.Cert)
	if e != nil {
		return kube{}, e
	}
	key, e := base64.StdEncoding.DecodeString(cfg.Users[0].User.Key)
	if e != nil {
		return kube{}, e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return kube{}, errors.New("invalid Kubernetes CA")
	}
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		return kube{}, e
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{pair}}}}
	return kube{&coordinator.KubernetesStore{BaseURL: "https://" + m.Config.OverlayIP + ":6443", Namespace: "deepai-system", Client: client}}, nil
}

type clusterBackend struct {
	kube
	credentialsDir string
}

func (b clusterBackend) Healthy(ctx context.Context, names []string) error {
	if err := b.call(ctx, "GET", "/readyz", nil, nil); err != nil {
		return err
	}
	for _, name := range names {
		if err := b.NodeReady(ctx, name); err != nil {
			return err
		}
	}
	return nil
}
func (b clusterBackend) NodeReady(ctx context.Context, name string) error {
	var node struct {
		Status struct {
			Conditions []struct{ Type, Status string }
		}
	}
	if err := b.call(ctx, "GET", "/api/v1/nodes/"+name, nil, &node); err != nil {
		return err
	}
	for _, c := range node.Status.Conditions {
		if c.Type == "Ready" && c.Status == "True" {
			return nil
		}
	}
	return errors.New("cluster member is not ready")
}
func (b clusterBackend) ValidateNode(ctx context.Context, n coordinator.Node, voter, mustBeReady bool) error {
	var node struct {
		Metadata struct{ Labels map[string]string }
		Status   struct {
			Addresses  []struct{ Type, Address string }
			Conditions []struct{ Type, Status string }
		}
	}
	err := b.call(ctx, "GET", "/api/v1/nodes/"+n.Hostname, nil, &node)
	if !mustBeReady {
		var api *kubeError
		if errors.As(err, &api) && api.Status == 404 {
			return nil
		}
		if err != nil {
			return err
		}
		return errors.New("Kubernetes node name already exists")
	}
	if err != nil {
		return err
	}
	if node.Metadata.Labels["connect.deepai.cloud/role"] != n.Role || node.Metadata.Labels["connect.deepai.cloud/voter"] != fmt.Sprint(voter) {
		return errors.New("Kubernetes node role differs from enrollment")
	}
	if n.Role == "hub" && node.Metadata.Labels[cluster.ProtectedRoleLabel] != "hub" {
		return errors.New("Kubernetes hub lacks administrator-approved scheduling role")
	}
	address := false
	ready := false
	for _, a := range node.Status.Addresses {
		for _, p := range n.Addresses {
			if a.Type == "InternalIP" && a.Address == p.Addr().String() {
				address = true
			}
		}
	}
	for _, c := range node.Status.Conditions {
		if c.Type == "Ready" && c.Status == "True" {
			ready = true
		}
	}
	if !address || !ready {
		return errors.New("Kubernetes node identity or readiness differs from enrollment")
	}
	return nil
}
func (b clusterBackend) Probe(ctx context.Context, ip netip.Addr, pub ed25519.PublicKey) error {
	return enrollment.Probe(ctx, ip, pub)
}
func (b clusterBackend) PodRoutes(ctx context.Context, name string) ([]netip.Prefix, error) {
	var n struct {
		Spec struct {
			PodCIDR  string   `json:"podCIDR"`
			PodCIDRs []string `json:"podCIDRs"`
		}
	}
	if err := b.call(ctx, "GET", "/api/v1/nodes/"+name, nil, &n); err != nil {
		return nil, err
	}
	return parsePodRoutes(n.Spec.PodCIDR, n.Spec.PodCIDRs)
}
func parsePodRoutes(single string, multiple []string) ([]netip.Prefix, error) {
	if len(multiple) == 0 && single != "" {
		multiple = []string{single}
	}
	if len(multiple) == 0 {
		return nil, errors.New("Kubernetes has not assigned a pod network to the node")
	}
	var routes []netip.Prefix
	for _, raw := range multiple {
		p, e := netip.ParsePrefix(raw)
		if e != nil || !p.Addr().Is4() || p != p.Masked() {
			return nil, errors.New("invalid Kubernetes pod CIDR")
		}
		routes = append(routes, p)
	}
	return routes, nil
}
func (b clusterBackend) Token(ctx context.Context, server bool) (string, error) {
	// Kubernetes projected Secret paths intentionally contain symlinks.
	data, err := os.ReadFile(filepath.Join(b.credentialsDir, "server-token"))
	if err != nil {
		return "", errors.New("cluster join credentials unavailable")
	}
	full := strings.TrimSpace(string(data))
	parts := strings.Split(full, "::")
	if len(parts) != 2 || len(parts[0]) != 67 || !strings.HasPrefix(parts[0], "K10") {
		return "", errors.New("invalid CA-pinned server credential")
	}
	if server {
		return full, nil
	}
	// Mint an expiring worker-only Kubernetes bootstrap credential; never hand
	// the server token to a worker. K3s consumes this standard bootstrap schema.
	raw := make([]byte, 11)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	encoded := hex.EncodeToString(raw)
	id, secret := encoded[:6], encoded[6:]
	doc := map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]string{"name": "bootstrap-token-" + id, "namespace": "kube-system"}, "type": "bootstrap.kubernetes.io/token", "stringData": map[string]string{"token-id": id, "token-secret": secret, "expiration": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339), "usage-bootstrap-authentication": "true", "usage-bootstrap-signing": "true", "auth-extra-groups": "system:bootstrappers:k3s:default-node-token", "description": "DeepAI Connect worker enrollment"}}
	if err := b.call(ctx, "POST", "/api/v1/namespaces/kube-system/secrets", doc, nil); err != nil {
		return "", err
	}
	return parts[0] + "::" + id + "." + secret, nil
}
