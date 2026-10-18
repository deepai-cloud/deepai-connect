// Package relay runs the upstream encrypted DERP transport and STUN service.
// Relay admission is checked against the coordinator; DERP never routes IP packets.
package relay

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/platform"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/stun"
	"tailscale.com/types/key"
)

type Config struct {
	Listen, STUNListen, VerifyURL, StateDir, KeyFile string
}

// Run is intended to run behind the hub's TLS gateway. Admission fails closed
// when Kubernetes is unavailable; existing authenticated sessions remain alive.
func Run(ctx context.Context, cfg Config) error {
	u, err := url.Parse(cfg.VerifyURL)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/verify" || (u.Scheme != "https" && !(u.Scheme == "http" && net.ParseIP(u.Hostname()).IsLoopback())) {
		return errors.New("relay requires an HTTPS or loopback coordinator /verify URL")
	}
	if cfg.StateDir == "" {
		return errors.New("relay requires a private state directory")
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:3340"
	}
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("unencrypted relay listener must bind loopback behind the HTTPS gateway")
	}
	if cfg.STUNListen == "" {
		cfg.STUNListen = ":3478"
	}
	unlock, err := platform.Lock(cfg.StateDir)
	if err != nil {
		return err
	}
	defer unlock()
	var private key.NodePrivate
	if cfg.KeyFile != "" {
		var raw []byte
		raw, err = os.ReadFile(cfg.KeyFile) // Kubernetes projected Secret.
		if err == nil {
			err = private.UnmarshalText(raw)
		}
		if err == nil && private.IsZero() {
			err = errors.New("empty relay key")
		}
	} else {
		private, err = loadIdentity(cfg.StateDir)
	}
	if err != nil {
		return err
	}
	s := derpserver.New(private, log.Printf)
	defer s.Close()
	s.SetVerifyClientURL(cfg.VerifyURL)
	s.SetVerifyClientURLFailOpen(false)
	mux := http.NewServeMux()
	mux.Handle("/derp", derpserver.Handler(s))
	mux.Handle("/derp/", derpserver.Handler(s))
	mux.HandleFunc("/generate_204", derpserver.ServeNoContent)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	stunAddr, err := net.ResolveUDPAddr("udp", cfg.STUNListen)
	if err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp", stunAddr)
	if err != nil {
		return err
	}
	defer udp.Close()
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 16 << 10}
	failed := make(chan error, 2)
	go func() { failed <- server.Serve(listener) }()
	go func() { failed <- serveSTUN(ctx, udp) }()
	select {
	case err = <-failed:
	case <-ctx.Done():
		err = ctx.Err()
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdown)
	return err
}

func loadIdentity(dir string) (key.NodePrivate, error) {
	path := filepath.Join(dir, "derp.key")
	b, err := platform.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		k := key.NewNode()
		b, err := k.MarshalText()
		if err != nil {
			return k, err
		}
		return k, platform.WriteFile(path, b, true)
	}
	if err != nil {
		return key.NodePrivate{}, err
	}
	var k key.NodePrivate
	if err := k.UnmarshalText(b); err != nil || k.IsZero() {
		return k, errors.New("invalid saved relay identity; restore its private backup")
	}
	return k, nil
}

func serveSTUN(ctx context.Context, conn *net.UDPConn) error {
	// Closing the owned socket wakes an idle reader immediately without a
	// periodic timer or resetting the read deadline for every STUN packet.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	buffer := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if tx, err := stun.ParseBindingRequest(buffer[:n]); err == nil {
			_, _ = conn.WriteToUDPAddrPort(stun.Response(tx, addr), addr)
		}
	}
}
