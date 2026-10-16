package coordinator

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"tailscale.com/control/controlhttp"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/zstdframe"
)

// Client speaks the same Noise/HTTP2 protocol as upstream Tailscale clients.
// ServerKey optionally pins the Noise identity. Otherwise discovery uses
// authenticated HTTPS (HTTP is allowed on loopback for bootstrap/tests).
// Each method owns and closes its Noise connection.
type Client struct {
	ServerURL  string
	MachineKey key.MachinePrivate
	ServerKey  key.MachinePublic
	HTTPClient *http.Client
}

func (c *Client) fetchKey(ctx context.Context, u *url.URL) (key.MachinePublic, error) {
	if !c.ServerKey.IsZero() {
		return c.ServerKey, nil
	}
	if u.Scheme != "https" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
		return key.MachinePublic{}, errors.New("unpinned coordinator requires HTTPS")
	}
	r, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(c.ServerURL, "/")+"/key?v="+fmt.Sprint(tailcfg.CurrentCapabilityVersion), nil)
	if err != nil {
		return key.MachinePublic{}, err
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	// Discovery must not silently leave the authenticated origin or downgrade
	// HTTPS while obtaining the trust anchor for the Noise handshake.
	client := *hc
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("coordinator key redirect forbidden") }
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	if standard, ok := transport.(*http.Transport); ok {
		// Discovery has the same one-operation connection lifetime as Noise.
		// Canceling an HTTP/2 request does not retire its pooled TCP connection;
		// after an uplink change, every poll can otherwise reuse the same dead
		// connection. Clone settings, not the pool, and close after this request.
		owned := standard.Clone()
		owned.DisableKeepAlives = true
		client.Transport = owned
		defer owned.CloseIdleConnections()
	}
	res, err := client.Do(r)
	if err != nil {
		return key.MachinePublic{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return key.MachinePublic{}, fmt.Errorf("coordinator key: HTTP %d", res.StatusCode)
	}
	var keys tailcfg.OverTLSPublicKeyResponse
	if err = json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&keys); err != nil {
		return key.MachinePublic{}, err
	}
	if keys.PublicKey.IsZero() {
		return key.MachinePublic{}, errors.New("coordinator returned empty Noise key")
	}
	return keys.PublicKey, nil
}

func (c *Client) connect(ctx context.Context) (*http2.ClientConn, io.Closer, error) {
	u, err := url.Parse(c.ServerURL)
	if err != nil {
		return nil, nil, err
	}
	if u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, nil, errors.New("coordinator URL must be an HTTP(S) origin")
	}
	if c.MachineKey.IsZero() {
		return nil, nil, errors.New("machine key required")
	}
	serverKey, err := c.fetchKey(ctx, u)
	if err != nil {
		return nil, nil, err
	}
	d := &controlhttp.Dialer{Hostname: u.Hostname(), MachineKey: c.MachineKey, ControlKey: serverKey, ProtocolVersion: uint16(tailcfg.CurrentCapabilityVersion)}
	if u.Scheme == "http" {
		d.HTTPPort = u.Port()
		if d.HTTPPort == "" {
			d.HTTPPort = "80"
		}
		d.HTTPSPort = controlhttp.NoPort
	} else {
		d.HTTPSPort = u.Port()
		if d.HTTPSPort == "" {
			d.HTTPSPort = "443"
		}
	}
	conn, err := d.Dial(ctx)
	if err != nil {
		return nil, nil, err
	}
	transport := &http2.Transport{}
	h2, err := transport.NewClientConn(conn)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	return h2, conn, nil
}

func (c *Client) request(ctx context.Context, path string, in any) (*http.Response, io.Closer, error) {
	h2, closer, err := c.connect(ctx)
	if err != nil {
		return nil, nil, err
	}
	b, err := json.Marshal(in)
	if err != nil {
		closer.Close()
		return nil, nil, err
	}
	r, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(c.ServerURL, "/")+path, bytes.NewReader(b))
	if err != nil {
		closer.Close()
		return nil, nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	res, err := h2.RoundTrip(r)
	if err != nil {
		closer.Close()
		return nil, nil, err
	}
	if res.StatusCode != 200 {
		res.Body.Close()
		closer.Close()
		return nil, nil, fmt.Errorf("coordinator %s: HTTP %d", path, res.StatusCode)
	}
	return res, closer, nil
}

func (c *Client) Register(ctx context.Context, req tailcfg.RegisterRequest) (*tailcfg.RegisterResponse, error) {
	if req.Version == 0 {
		req.Version = tailcfg.CurrentCapabilityVersion
	}
	res, closer, err := c.request(ctx, "/machine/register", &req)
	if err != nil {
		return nil, err
	}
	defer closer.Close()
	defer res.Body.Close()
	var reply tailcfg.RegisterResponse
	if err = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&reply); err != nil {
		return nil, err
	}
	if reply.Error != "" {
		return &reply, fmt.Errorf("registration: %s", reply.Error)
	}
	return &reply, nil
}

func (c *Client) Map(ctx context.Context, req tailcfg.MapRequest) (*tailcfg.MapResponse, error) {
	req.Stream = false
	if req.Version == 0 {
		req.Version = tailcfg.CurrentCapabilityVersion
	}
	res, closer, err := c.request(ctx, "/machine/map", &req)
	if err != nil {
		return nil, err
	}
	defer closer.Close()
	defer res.Body.Close()
	if req.OmitPeers && !req.ReadOnly {
		_, err = io.Copy(io.Discard, res.Body)
		return nil, err
	}
	return readMap(res.Body, req.Compress == "zstd")
}

// Stream returns on disconnect; callers reconnect with backoff. Every new
// stream starts with a complete map, so no process-local session is required on
// the next replica. fn should persist successfully applied snapshots locally.
func (c *Client) Stream(ctx context.Context, req tailcfg.MapRequest, fn func(*tailcfg.MapResponse) error) error {
	req.Stream = true
	req.ReadOnly = false
	req.KeepAlive = true
	if req.Version == 0 {
		req.Version = tailcfg.CurrentCapabilityVersion
	}
	res, closer, err := c.request(ctx, "/machine/map", &req)
	if err != nil {
		return err
	}
	defer closer.Close()
	defer res.Body.Close()
	for {
		msg, err := readMap(res.Body, req.Compress == "zstd")
		if err != nil {
			return err
		}
		if msg.KeepAlive {
			continue
		}
		if err = fn(msg); err != nil {
			return err
		}
	}
}

func readMap(r io.Reader, compressed bool) (*tailcfg.MapResponse, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, err
	}
	size := binary.LittleEndian.Uint32(prefix[:])
	if size == 0 || size > 16<<20 {
		return nil, errors.New("invalid map frame size")
	}
	b := make([]byte, int(size))
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	if compressed {
		var err error
		b, err = zstdframe.AppendDecode(nil, b, zstdframe.MaxDecodedSize(16<<20))
		if err != nil {
			return nil, err
		}
	}
	var msg tailcfg.MapResponse
	if err := json.Unmarshal(b, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}
