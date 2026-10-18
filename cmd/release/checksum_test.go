package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestChecksumFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact")
	for _, size := range []int{0, 1, 32767, 32768, 32769, 1 << 20} {
		data := bytes.Repeat([]byte{0x5a}, size)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		digest, gotSize, err := checksumFile(path)
		if err != nil || gotSize != int64(size) || digest != fmt.Sprintf("%x", sha256.Sum256(data)) {
			t.Fatalf("size %d: digest=%s size=%d err=%v", size, digest, gotSize, err)
		}
	}
	if _, _, err := checksumFile(path + "-missing"); !os.IsNotExist(err) {
		t.Fatalf("missing artifact: %v", err)
	}
	if _, _, err := checksumFile(filepath.Dir(path)); err == nil {
		t.Fatal("directory accepted as an artifact")
	}
}

func BenchmarkChecksumFile(b *testing.B) {
	const size = 32 << 20
	path := filepath.Join(b.TempDir(), "artifact")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x5a}, size), 0600); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(size)
	for b.Loop() {
		if _, _, err := checksumFile(path); err != nil {
			b.Fatal(err)
		}
	}
}
