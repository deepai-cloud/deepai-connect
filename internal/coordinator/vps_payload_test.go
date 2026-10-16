//go:build vpsintegration

package coordinator

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestVPSPayloadNeverRetriesTruncatedResponse(t *testing.T) {
	body := []byte("complete acceptance response")
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		if requests.Add(1) == 1 {
			_, _ = w.Write(body[:5])
			return
		}
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	client := srv.Client()
	client.Timeout = time.Second
	target := vpsTarget{url: srv.URL, digest: sha256.Sum256(body)}
	if err := vpsCheckPayload(context.Background(), client, target); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated transfer did not fail: %v", err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("partial transfer was hidden by %d requests", got)
	}
	if err := vpsCheckPayload(context.Background(), client, target); err != nil {
		t.Fatalf("separate complete transfer failed: %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("expected one request per probe, got %d", got)
	}
}

func TestVPSPayloadDoesNotRetryHTTPOrTransportFailures(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusOK} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.WriteHeader(status)
				_, _ = w.Write([]byte("wrong response"))
			}))
			defer srv.Close()
			target := vpsTarget{url: srv.URL, digest: sha256.Sum256([]byte("expected response"))}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := vpsCheckPayload(ctx, srv.Client(), target); err == nil {
				t.Fatal("unsuccessful response accepted")
			}
			if got := requests.Load(); got != 1 {
				t.Fatalf("unsuccessful response retried: %d requests", got)
			}
		})
	}
	var dials atomic.Int32
	failure := errors.New("test connection failure")
	client := &http.Client{Transport: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, failure
	}}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := vpsCheckPayload(ctx, client, vpsTarget{url: "http://127.0.0.1/"}); !errors.Is(err, failure) {
		t.Fatalf("transport failure was lost: %v", err)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("failed request retried: %d dials", got)
	}
}
