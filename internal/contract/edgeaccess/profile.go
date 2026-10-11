// Package edgeaccess defines DeepAI Connect's versioned application publishing credential.
package edgeaccess

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/platform"
)

// Profile is a bearer credential for a trusted owner's public app publishers.
// It grants all configured application domains; it is not tenant isolation.
type Profile struct {
	Version int      `json:"version"`
	Server  string   `json:"server"`
	Port    int      `json:"port"`
	Token   string   `json:"token"`
	CA      string   `json:"ca"`
	Domains []string `json:"domains"`
}

func Read(path string) (Profile, error) {
	var a Profile
	b, err := platform.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(b, &a)
	}
	if err != nil {
		return a, err
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			return a, err
		}
		if info.Mode().Perm()&0077 != 0 {
			return a, errors.New("edge access file must be private (chmod 600)")
		}
	}
	return a, a.Validate()
}

func (a Profile) Validate() error {
	if err := a.ValidateIdentity(); err != nil {
		return err
	}
	cert, _ := parseCA(a.CA)
	if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
		return errors.New("edge CA is not currently valid")
	}
	return nil
}

// ValidateIdentity permits stopping an existing publisher after its trust
// expires. Starting new connections must additionally call Validate.
func (a Profile) ValidateIdentity() error {
	if a.Version != 1 || !ValidDomain(a.Server) || a.Port != 7000 || !validSecret(a.Token) || len(a.Domains) == 0 || len(a.Domains) > 32 {
		return errors.New("invalid edge access profile")
	}
	for i, d := range a.Domains {
		if !ValidDomain(d) || d == a.Server || slices.Contains(a.Domains[:i], d) {
			return errors.New("invalid edge application domain")
		}
	}
	_, err := parseCA(a.CA)
	return err
}

func parseCA(raw string) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(raw))
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("invalid edge CA")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA || cert.CheckSignatureFrom(cert) != nil {
		return nil, errors.New("invalid edge CA")
	}
	return cert, nil
}

func ValidDomain(d string) bool {
	if len(d) > 253 || strings.ToLower(d) != d || !strings.Contains(d, ".") || net.ParseIP(d) != nil {
		return false
	}
	for _, part := range strings.Split(d, ".") {
		if len(part) == 0 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func validSecret(s string) bool { b, e := hex.DecodeString(s); return e == nil && len(b) == 32 }
