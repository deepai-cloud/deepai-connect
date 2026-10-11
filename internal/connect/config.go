// Package connect runs an owner-operated Headscale, DERP and HTTPS application edge.
package connect

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/mail"
	"slices"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/contract/edgeaccess"
)

const (
	HeadscaleImage = "ghcr.io/juanfont/headscale:0.29.4"
	CaddyImage     = "caddy:2.11.6-alpine"
	FRPSImage      = "ghcr.io/fatedier/frps:v0.71.0"
	label          = "cloud.deepai.connect"
)

func secret(s string) bool { b, e := hex.DecodeString(s); return e == nil && len(b) == 32 }
func random() string       { b := make([]byte, 32); rand.Read(b); return hex.EncodeToString(b) }
func encoded(v any) []byte { b, _ := json.MarshalIndent(v, "", "  "); return append(b, '\n') }

func validConfig(s State) error {
	ip := net.ParseIP(s.PublicIP)
	if !edgeaccess.ValidDomain(s.Domain) || ip == nil || ip.To4() == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || net.ParseIP("100.64.0.0").Equal(ip) {
		return errors.New("server requires a lowercase public domain and a public IPv4 address")
	}
	_, cgnat, _ := net.ParseCIDR("100.64.0.0/10")
	if cgnat.Contains(ip) {
		return errors.New("server address must be publicly routable")
	}
	a, err := mail.ParseAddress(s.Email)
	if err != nil || a.Address != s.Email {
		return errors.New("server requires an ACME contact email address")
	}
	if len(s.Apps) > 32 {
		return errors.New("at most 32 explicit application domains are supported")
	}
	for i, d := range s.Apps {
		if !edgeaccess.ValidDomain(d) || d == s.Domain || slices.Contains(s.Apps[:i], d) {
			return errors.New("app domains must be distinct lowercase DNS names, different from the mesh domain")
		}
	}
	return nil
}

func certificates(host string) (caPEM, certPEM, keyPEM string, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	serial := func() *big.Int { n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)); return n }
	ca := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "DeepAI Connect private edge CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return
	}
	leaf := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: ca.NotBefore, NotAfter: time.Now().AddDate(5, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		return
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return
	}
	caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return
}

func headscaleConfig(s State) []byte {
	return encoded(map[string]any{
		"server_url": "https://" + s.Domain, "listen_addr": "0.0.0.0:8080", "metrics_listen_addr": "", "grpc_listen_addr": "127.0.0.1:50443",
		"noise":       map[string]any{"private_key_path": "/var/lib/headscale/noise_private.key"},
		"prefixes":    map[string]any{"v4": "100.64.0.0/10", "v6": "fd7a:115c:a1e0::/48"},
		"derp":        map[string]any{"server": map[string]any{"enabled": true, "region_id": 999, "region_code": "deepai", "region_name": "DeepAI Connect private relay", "verify_clients": true, "stun_listen_addr": "0.0.0.0:3478", "private_key_path": "/var/lib/headscale/derp.key", "automatically_add_embedded_derp_region": true, "ipv4": s.PublicIP}, "urls": []string{}, "paths": []string{}, "auto_update_enabled": false},
		"database":    map[string]any{"type": "sqlite", "sqlite": map[string]any{"path": "/var/lib/headscale/db.sqlite", "write_ahead_log": true}},
		"dns":         map[string]any{"magic_dns": false, "override_local_dns": false},
		"policy":      map[string]any{"mode": "file", "path": "/etc/headscale/policy.json"},
		"unix_socket": "/var/lib/headscale/headscale.sock", "unix_socket_permission": "0600", "disable_check_updates": true,
		"logtail": map[string]any{"enabled": false}, "log": map[string]string{"level": "warn"},
	})
}

func caddyConfig(s State) []byte {
	route := func(hosts []string, target string) any {
		return map[string]any{"match": []any{map[string]any{"host": hosts}}, "handle": []any{map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]string{"dial": target}}, "stream_timeout": "0s"}}, "terminal": true}
	}
	routes := []any{route([]string{s.Domain}, s.name("headscale")+":8080")}
	if len(s.Apps) > 0 {
		routes = append(routes, route(s.Apps, s.name("frps")+":8080"))
	}
	return encoded(map[string]any{"admin": map[string]any{"disabled": true}, "apps": map[string]any{
		// Caddy 2.11.6's new idle body/write wrappers regress HTTP/2 and long
		// streams. Negative values disable them; zero restores its defaults.
		"http": map[string]any{"servers": map[string]any{"edge": map[string]any{"listen": []string{":443"}, "routes": routes, "read_idle_timeout": "-1s", "write_idle_timeout": "-1s", "read_header_timeout": "30s", "max_header_bytes": 1048576}}},
		"tls":  map[string]any{"automation": map[string]any{"policies": []any{map[string]any{"subjects": append([]string{s.Domain}, s.Apps...), "issuers": []any{map[string]string{"module": "acme", "email": s.Email}}}}}},
	}})
}

func frpsConfig(s State) []byte {
	return encoded(map[string]any{"bindAddr": "0.0.0.0", "bindPort": 7000, "vhostHTTPPort": 8080,
		"transport": map[string]any{"tls": map[string]any{"force": true, "certFile": "/etc/deepai/server.crt", "keyFile": "/etc/deepai/server.key"}},
		"auth":      map[string]any{"method": "token", "token": s.Token, "additionalScopes": []string{"HeartBeats", "NewWorkConns"}},
		"log":       map[string]string{"to": "console", "level": "warn"}, "detailedErrorsToClient": false,
	})
}
