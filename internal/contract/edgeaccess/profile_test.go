package edgeaccess

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// This public fixture pins the version-one wire contract. Its token is fake,
// and no private key for the fixture CA is retained.
func versionOneFixture(t *testing.T) (Profile, []byte) {
	t.Helper()
	b, err := os.ReadFile("testdata/profile-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var p Profile
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	return p, b
}

func TestVersionOneWireContract(t *testing.T) {
	p, fixture := versionOneFixture(t)
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	// Compare JSON values, so the fixture pins field names and values without
	// making whitespace or object key order part of the wire contract.
	var want, got map[string]any
	if err := json.Unmarshal(fixture, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("version-one wire profile changed")
	}
}

func TestInvalidProfileFieldsRejected(t *testing.T) {
	cases := map[string]func(*Profile){
		"missing version":       func(p *Profile) { p.Version = 0 },
		"future version":        func(p *Profile) { p.Version = 2 },
		"negative version":      func(p *Profile) { p.Version = -1 },
		"empty server":          func(p *Profile) { p.Server = "" },
		"IP server":             func(p *Profile) { p.Server = "127.0.0.1" },
		"IPv6 server":           func(p *Profile) { p.Server = "::1" },
		"URL server":            func(p *Profile) { p.Server = "https://mesh.example.test" },
		"uppercase server":      func(p *Profile) { p.Server = "Mesh.example.test" },
		"single label server":   func(p *Profile) { p.Server = "localhost" },
		"shell server":          func(p *Profile) { p.Server = "mesh.$(id).test" },
		"newline server":        func(p *Profile) { p.Server = "mesh.example.test\nattacker.test" },
		"userinfo server":       func(p *Profile) { p.Server = "owner@mesh.example.test" },
		"wrong port":            func(p *Profile) { p.Port = 443 },
		"missing token":         func(p *Profile) { p.Token = "" },
		"short token":           func(p *Profile) { p.Token = strings.Repeat("a", 62) },
		"long token":            func(p *Profile) { p.Token = strings.Repeat("a", 66) },
		"nonhex token":          func(p *Profile) { p.Token = strings.Repeat("z", 64) },
		"token whitespace":      func(p *Profile) { p.Token += "\n" },
		"no domains":            func(p *Profile) { p.Domains = nil },
		"empty domain":          func(p *Profile) { p.Domains = []string{""} },
		"duplicate domains":     func(p *Profile) { p.Domains = []string{"app.example.test", "app.example.test"} },
		"server as application": func(p *Profile) { p.Domains = []string{p.Server} },
		"wildcard domain":       func(p *Profile) { p.Domains = []string{"*.example.test"} },
		"IP application":        func(p *Profile) { p.Domains = []string{"192.0.2.1"} },
		"uppercase application": func(p *Profile) { p.Domains = []string{"App.example.test"} },
		"path in application":   func(p *Profile) { p.Domains = []string{"app.example.test/private"} },
		"port in application":   func(p *Profile) { p.Domains = []string{"app.example.test:443"} },
		"empty DNS label":       func(p *Profile) { p.Domains = []string{"app..test"} },
		"leading DNS hyphen":    func(p *Profile) { p.Domains = []string{"-app.example.test"} },
		"trailing DNS hyphen":   func(p *Profile) { p.Domains = []string{"app-.example.test"} },
		"long DNS label":        func(p *Profile) { p.Domains = []string{strings.Repeat("a", 64) + ".test"} },
		"long domain":           func(p *Profile) { p.Domains = []string{strings.Repeat(strings.Repeat("a", 63)+".", 4) + "test"} },
		"missing CA":            func(p *Profile) { p.CA = "" },
		"invalid CA":            func(p *Profile) { p.CA = "not a certificate" },
		"invalid certificate":   func(p *Profile) { p.CA = "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n" },
		"private key block":     func(p *Profile) { p.CA = "-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n" },
		"extra certificate":     func(p *Profile) { p.CA += p.CA },
		"trailing CA data":      func(p *Profile) { p.CA += "untrusted data" },
		"invalid CA signature": func(p *Profile) {
			block, _ := pem.Decode([]byte(p.CA))
			block.Bytes[len(block.Bytes)-1] ^= 1
			p.CA = string(pem.EncodeToMemory(block))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p, _ := versionOneFixture(t)
			mutate(&p)
			if p.ValidateIdentity() == nil || p.Validate() == nil {
				t.Fatal("invalid profile accepted")
			}
		})
	}
	p, _ := versionOneFixture(t)
	p.Domains = nil
	for i := range 32 {
		p.Domains = append(p.Domains, fmt.Sprintf("app-%d.example.test", i))
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("32 distinct domains must remain supported: %v", err)
	}
	p.Domains = append(p.Domains, "overflow.example.test")
	if p.ValidateIdentity() == nil {
		t.Fatal("more than 32 application domains accepted")
	}
}

func TestCertificateValidityAndCleanupIdentity(t *testing.T) {
	for name, dates := range map[string][2]time.Time{
		"expired": {time.Now().Add(-2 * time.Hour), time.Now().Add(-time.Hour)},
		"future":  {time.Now().Add(time.Hour), time.Now().Add(2 * time.Hour)},
	} {
		t.Run(name, func(t *testing.T) {
			p, _ := versionOneFixture(t)
			p.CA = testCertificate(t, true, dates[0], dates[1])
			if err := p.ValidateIdentity(); err != nil {
				t.Fatalf("valid identity must allow publisher cleanup: %v", err)
			}
			if p.Validate() == nil {
				t.Fatal("inactive trust accepted for a new connection")
			}
			if _, err := Read(writeProfile(t, p)); err == nil {
				t.Fatal("read accepted inactive trust")
			}
		})
	}
	p, _ := versionOneFixture(t)
	p.CA = testCertificate(t, false, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if p.ValidateIdentity() == nil {
		t.Fatal("leaf certificate accepted as a CA")
	}
}

func TestReadProfilePermissionsAndIdentity(t *testing.T) {
	p, _ := versionOneFixture(t)
	path := writeProfile(t, p)
	read, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(read, p) {
		t.Fatal("read changed publishing identity")
	}
	if runtime.GOOS == "windows" {
		return // POSIX permission bits do not describe Windows ACLs.
	}
	for _, mode := range []os.FileMode{0400, 0600, 0640, 0604, 0666} {
		t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			_, err := Read(path)
			if private := mode&0077 == 0; (err == nil) != private {
				t.Fatalf("private=%t, read error=%v", private, err)
			}
		})
	}
}

func TestReadRejectsMalformedOrUnsafeFiles(t *testing.T) {
	p, _ := versionOneFixture(t)
	path := writeProfile(t, p)
	p.Version = 2
	if _, err := Read(writeProfile(t, p)); err == nil {
		t.Fatal("read accepted an unsupported profile version")
	}
	if _, err := Read(filepath.Dir(path)); err == nil {
		t.Fatal("directory accepted as a credential")
	}
	if _, err := Read(path + ".missing"); err == nil {
		t.Fatal("missing credential accepted")
	}
	if runtime.GOOS != "windows" {
		link := path + ".link"
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(link); err == nil {
			t.Fatal("symlink accepted as a credential")
		}
	}
	for _, raw := range []string{"{", "null", "{}", `{"version":"1"}`, `{"port":7000.5}`, `{"domains":"app.example.test"}`} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(path); err == nil {
			t.Fatalf("invalid JSON credential accepted: %s", raw)
		}
	}
}

func writeProfile(t *testing.T, p Profile) string {
	t.Helper()
	// macOS temp directories may have symlinked ancestors. Resolve those here
	// so Read's independent link rejection remains exercised intentionally.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testCertificate(t *testing.T, isCA bool, notBefore, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: isCA, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: notBefore, NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
