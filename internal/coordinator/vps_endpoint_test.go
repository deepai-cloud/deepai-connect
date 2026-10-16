//go:build vpsintegration

package coordinator

import (
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestVPSNativeEndpointPublishesPrivateURLAndExactPayload(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "native.url")
	var actualAddress string
	listen := func(network, address string) (net.Listener, error) {
		if network != "tcp" || address != "100.64.0.7:18081" {
			t.Fatalf("listener escaped its private overlay address: %s %s", network, address)
		}
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err == nil {
			actualAddress = l.Addr().String()
		}
		return l, err
	}
	closeEndpoint, err := vpsStartNativeEndpoint(t, listen, netip.MustParseAddr("100.64.0.7"), path, "reverse-path-verified\n")
	if err != nil {
		t.Fatal(err)
	}
	defer closeEndpoint()
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "http://100.64.0.7:18081/\n" {
		t.Fatalf("endpoint file = %q, err = %v", b, err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("endpoint permissions are not private: %v", err)
	}
	resp, err := http.Get("http://" + actualAddress + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || string(b) != "reverse-path-verified\n" {
		t.Fatalf("response changed expected bytes: %q, err = %v", b, err)
	}
	closeEndpoint()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("endpoint marker survived listener shutdown")
	}
}

func TestVPSNativeEndpointRefusesExistingOrPublicFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "native.url")
	if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	listen := func(string, string) (net.Listener, error) {
		t.Fatal("invalid endpoint configuration started a listener")
		return nil, nil
	}
	if _, err := vpsStartNativeEndpoint(t, listen, netip.MustParseAddr("100.64.0.7"), path, "body"); err == nil {
		t.Fatal("existing file was accepted")
	}
	b, _ := os.ReadFile(path)
	if string(b) != "preserve" {
		t.Fatal("existing file was changed")
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := vpsStartNativeEndpoint(t, listen, netip.MustParseAddr("100.64.0.7"), filepath.Join(dir, "new.url"), "body"); err == nil {
		t.Fatal("public parent directory was accepted")
	}
}
