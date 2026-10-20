package unified

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestCloudBundleRejectsMalformedAndTruncatedTransport(t *testing.T) {
	_, c := cloudFixture(t)
	valid, err := json.Marshal(&cloudBundle{Cloud: c})
	if err != nil {
		t.Fatal(err)
	}
	oversized := append(bytes.Clone(valid), bytes.Repeat([]byte(" "), maxCloudBundleSize-len(valid))...)
	oversized = append(oversized, []byte(`{"cloud":null}`)...)
	for name, raw := range map[string][]byte{
		"empty":                   nil,
		"null":                    []byte("null"),
		"wrong-shape":             []byte("[]"),
		"missing-cloud":           []byte(`{"policy":[]}`),
		"unknown-field":           []byte(`{"cloud":null,"unexpected":true}`),
		"unknown-nested-field":    bytes.Replace(valid, []byte(`"role":"worker"`), []byte(`"role":"worker","execute":"anything"`), 1),
		"two-documents":           append(bytes.Clone(valid), []byte("{}")...),
		"trailing-garbage":        append(bytes.Clone(valid), []byte("!")...),
		"truncated":               valid[:len(valid)-1],
		"oversize-valid-prefix":   oversized,
		"missing-declared-policy": bytes.Replace(valid, []byte(`"domain":`), []byte(`"packetPolicyFile":"policy.json","domain":`), 1),
		"key-without-certificate": bytes.Replace(valid, []byte(`"policy":null`), []byte(`"policy":null,"key":"c2VjcmV0"`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if b, err := decodeCloudBundle(bytes.NewReader(raw)); err == nil || b != nil {
				t.Fatal("malformed bundle returned usable input")
			}
		})
	}
	if b, err := decodeCloudBundle(bytes.NewReader(valid)); err != nil || b.Cloud.Name != c.Name {
		t.Fatalf("valid bundle failed: %v", err)
	}
}

type failCloudRead struct{}

func (failCloudRead) Read([]byte) (int, error) { return 0, errors.New("private-input-content") }

func TestCloudBundleReadFailureDoesNotExposeInput(t *testing.T) {
	b, err := decodeCloudBundle(failCloudRead{})
	if b != nil || err == nil || strings.Contains(err.Error(), "private-input-content") {
		t.Fatal("transport failure leaked input or returned a partial bundle")
	}
}

func TestCloudBundleReadIsBounded(t *testing.T) {
	reader := &countCloudRead{Reader: io.MultiReader(strings.NewReader("{}"), strings.NewReader(strings.Repeat(" ", maxCloudBundleSize*2)))}
	if _, err := decodeCloudBundle(reader); err == nil {
		t.Fatal("oversized bundle accepted")
	}
	if reader.n != maxCloudBundleSize+1 {
		t.Fatalf("read %d bytes; expected bounded sentinel read", reader.n)
	}
}

type countCloudRead struct {
	io.Reader
	n int
}

func (r *countCloudRead) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.n += n
	return n, err
}
