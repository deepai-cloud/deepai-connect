package connect

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/deepai-cloud/deepai-connect/internal/contract/edgeaccess"
)

func clientOptions(h *Server) accessOptions {
	return accessOptions{Format: "frpc", Domain: h.Apps[0], LocalIP: "127.0.0.1", LocalPort: 8080}
}

func TestFRPCBundleUsesPrivateFilesAndAuthenticatedTLS(t *testing.T) {
	h := fixture(t)
	parent := t.TempDir()
	if err := os.Chmod(parent, 0755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(parent, "client")
	o := clientOptions(h)
	if err := h.exportAccess(out, o); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(out)
	if err != nil || len(entries) != 3 {
		t.Fatal("bundle must contain exactly its config, token, and CA", err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
			t.Fatal("bundle file is not private and regular", err)
		}
	}
	if info, err := os.Stat(out); err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0700 {
		t.Fatal("bundle directory is not private", err)
	}
	if info, err := os.Stat(parent); err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0755 {
		t.Fatal("export changed parent directory permissions", err)
	}
	for name, want := range map[string]string{"token": h.Token, "ca.pem": h.CA} {
		data, err := os.ReadFile(filepath.Join(out, name))
		if err != nil || string(data) != want {
			t.Fatalf("incorrect %s file", name)
		}
	}
	data, err := os.ReadFile(filepath.Join(out, "frpc.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(h.Token)) || bytes.Contains(data, []byte(h.Key)) || bytes.Contains(data, []byte(h.CA)) {
		t.Fatal("FRPC configuration embeds credential material")
	}
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if config["serverAddr"] != h.Domain || config["serverPort"] != float64(7000) || config["loginFailExit"] != true || config["webServer"] != nil {
		t.Fatal("unexpected server or admin listener settings")
	}
	auth := config["auth"].(map[string]any)
	if auth["method"] != "token" || auth["token"] != nil || !reflect.DeepEqual(auth["additionalScopes"], []any{"HeartBeats", "NewWorkConns"}) {
		t.Fatal("token authentication does not match the server")
	}
	if !reflect.DeepEqual(auth["tokenSource"], map[string]any{"type": "file", "file": map[string]any{"path": "./token"}}) {
		t.Fatal("token is not read from a relative file")
	}
	tls := config["transport"].(map[string]any)["tls"]
	if !reflect.DeepEqual(tls, map[string]any{"enable": true, "trustedCaFile": "./ca.pem", "serverName": h.Domain}) {
		t.Fatal("server authentication is not pinned to this server")
	}
	proxies := config["proxies"].([]any)
	if len(proxies) != 1 || !reflect.DeepEqual(proxies[0], map[string]any{
		"name": o.Domain, "type": "http", "customDomains": []any{o.Domain}, "localIP": o.LocalIP, "localPort": float64(o.LocalPort),
	}) {
		t.Fatal("bundle must publish only the selected domain and HTTP backend")
	}
}

func TestProfileExportRetainsVersionOneWireFormat(t *testing.T) {
	h := fixture(t)
	out := filepath.Join(t.TempDir(), "profile.json")
	if err := h.exportAccess(out, accessOptions{Format: "profile"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	want := encoded(edgeaccess.Profile{Version: 1, Server: h.Domain, Port: 7000, Token: h.Token, CA: h.CA, Domains: h.Apps})
	if err != nil || !bytes.Equal(data, want) {
		t.Fatal("profile format changed", err)
	}
	if err := h.exportAccess(out, accessOptions{Format: "profile"}); err == nil {
		t.Fatal("overwrote an existing publishing profile")
	}
}

func TestFRPCAllowsOwnerSelectedHTTPBackends(t *testing.T) {
	h := fixture(t)
	for _, backend := range []struct {
		ip   string
		port int
	}{{"127.0.0.1", 1}, {"10.0.0.8", 80}, {"8.8.8.8", 6443}, {"::1", 8080}, {"fd00::1", 65535}, {"2001:db8::1", 8080}} {
		t.Run(backend.ip, func(t *testing.T) {
			o := clientOptions(h)
			o.LocalIP, o.LocalPort = backend.ip, backend.port
			if err := h.exportAccess(filepath.Join(t.TempDir(), "client"), o); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAccessRejectsInvalidOptionsBeforeWriting(t *testing.T) {
	tests := map[string]func(*Server, *accessOptions){
		"unknown format":       func(_ *Server, o *accessOptions) { o.Format = "toml" },
		"missing domain":       func(_ *Server, o *accessOptions) { o.Domain = "" },
		"unconfigured domain":  func(_ *Server, o *accessOptions) { o.Domain = "other.example.com" },
		"wildcard domain":      func(_ *Server, o *accessOptions) { o.Domain = "*.example.com" },
		"mesh domain":          func(h *Server, o *accessOptions) { o.Domain = h.Domain },
		"hostname backend":     func(_ *Server, o *accessOptions) { o.LocalIP = "localhost" },
		"backend with port":    func(_ *Server, o *accessOptions) { o.LocalIP = "127.0.0.1:80" },
		"unspecified IPv4":     func(_ *Server, o *accessOptions) { o.LocalIP = "0.0.0.0" },
		"unspecified IPv6":     func(_ *Server, o *accessOptions) { o.LocalIP = "::" },
		"multicast backend":    func(_ *Server, o *accessOptions) { o.LocalIP = "224.0.0.1" },
		"zero port":            func(_ *Server, o *accessOptions) { o.LocalPort = 0 },
		"negative port":        func(_ *Server, o *accessOptions) { o.LocalPort = -1 },
		"oversized port":       func(_ *Server, o *accessOptions) { o.LocalPort = 65536 },
		"no application names": func(h *Server, _ *accessOptions) { h.Apps = nil },
		"invalid token":        func(h *Server, _ *accessOptions) { h.Token = "short" },
		"invalid CA":           func(h *Server, _ *accessOptions) { h.CA = "invalid" },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			h := fixture(t)
			o := clientOptions(h)
			change(h, &o)
			dir := t.TempDir()
			err := h.exportAccess(filepath.Join(dir, "client"), o)
			if err == nil {
				t.Fatal("accepted invalid export")
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 0 {
				t.Fatal("invalid export wrote output")
			}
		})
	}
	h := fixture(t)
	h.Apps = nil
	if err := h.exportAccess(filepath.Join(t.TempDir(), "profile.json"), accessOptions{Format: "profile"}); err == nil || !strings.Contains(err.Error(), "no configured application domains") {
		t.Fatal("profile export did not explain missing application domains", err)
	}
}

func TestAccessCLIRejectsWrongFlagsBeforeCreatingState(t *testing.T) {
	for _, args := range [][]string{
		{"access", "--format", "toml"},
		{"access", "--format", "frpc"},
		{"access", "--local-port", "8080"},
		{"access", "--domain", "app.example.com"},
		{"access", "--format", "frpc", "--domain", "app.example.com", "--local-port", "0"},
		{"access", "--format", "frpc", "--domain", "app.example.com", "--local-ip", "localhost"},
		{"access", "--format", "frpc", "--public-ip", "8.8.8.8"},
		{"invite", "--format", "frpc"},
		{"up", "--format", "frpc"},
		{"status", "--local-ip", "127.0.0.1"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			dir := t.TempDir()
			args := append(append([]string{}, args...), "--out", filepath.Join(dir, "client"), "--dir", filepath.Join(dir, "state"))
			if err := Run(context.Background(), args); err == nil {
				t.Fatal("accepted invalid flags")
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 0 {
				t.Fatal("invalid command created private state or credentials")
			}
		})
	}
}

func TestFRPCBundleNeverReusesExistingDestination(t *testing.T) {
	for _, kind := range []string{"file", "empty directory", "nonempty directory"} {
		t.Run(kind, func(t *testing.T) {
			h := fixture(t)
			parent := t.TempDir()
			out := filepath.Join(parent, "client")
			sentinel := out
			if kind != "file" {
				if err := os.Mkdir(out, 0755); err != nil {
					t.Fatal(err)
				}
				sentinel = filepath.Join(out, "token")
			}
			if kind != "empty directory" {
				if err := os.WriteFile(sentinel, []byte("existing"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.Stat(out)
			if err := h.exportAccess(out, clientOptions(h)); err == nil {
				t.Fatal("reused existing output")
			}
			after, _ := os.Stat(out)
			if before.Mode() != after.Mode() {
				t.Fatal("changed existing output permissions")
			}
			if kind != "empty directory" {
				data, err := os.ReadFile(sentinel)
				if err != nil || string(data) != "existing" {
					t.Fatal("changed existing file", err)
				}
			}
		})
	}
}

func TestFRPCBundleRefusesSymlinkAndMissingParents(t *testing.T) {
	h := fixture(t)
	parent := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(parent, "linked")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	dangling := filepath.Join(parent, "dangling")
	if err := os.Symlink(filepath.Join(outside, "missing"), dangling); err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{link, filepath.Join(link, "client"), dangling, filepath.Join(parent, "missing", "client")} {
		if err := h.exportAccess(out, clientOptions(h)); err == nil {
			t.Fatalf("accepted unsafe or missing path %s", out)
		}
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Fatal("wrote through a symlink")
	}
	if _, err := os.Stat(filepath.Join(parent, "missing")); !os.IsNotExist(err) {
		t.Fatal("created missing parent directory")
	}
}

func TestFRPCBundleConcurrentExportHasOneWinner(t *testing.T) {
	h := fixture(t)
	out := filepath.Join(t.TempDir(), "client")
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if h.exportAccess(out, clientOptions(h)) == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d exports succeeded; expected exactly one", wins.Load())
	}
	entries, err := os.ReadDir(out)
	if err != nil || len(entries) != 3 {
		t.Fatal("winner's bundle is incomplete", err)
	}
}

func TestFRPCBundleFailurePreservesAndReportsPrivatePartialOutput(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(parent, "client")
	secret := []byte("private-token")
	err = writeClientBundle(out, []bundleFile{{"token", secret}, {"token", []byte("replacement")}})
	if err == nil || !strings.Contains(err.Error(), out) || !strings.Contains(err.Error(), "private partial output") || strings.Contains(err.Error(), string(secret)) {
		t.Fatal("partial export failure lacks a safe recovery message", err)
	}
	data, err := os.ReadFile(filepath.Join(out, "token"))
	if err != nil || !bytes.Equal(data, secret) {
		t.Fatal("failed export replaced or deleted a completed private file", err)
	}
	info, err := os.Stat(filepath.Join(out, "token"))
	if err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal("partial credential is not private", err)
	}
	if err := writeClientBundle(out, []bundleFile{{"frpc.json", []byte("{}")}}); err == nil {
		t.Fatal("adopted partial output on retry")
	}
}
