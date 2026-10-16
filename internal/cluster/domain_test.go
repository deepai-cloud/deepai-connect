package cluster

import (
	"strings"
	"testing"
)

func TestPublicDomainValidation(t *testing.T) {
	longest := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	for _, domain := range []string{"mesh.example.com", "relay-2.example.com", "xn--bcher-kva.example", longest} {
		if !ValidDomain(domain) {
			t.Errorf("valid DNS name rejected: %q", domain)
		}
	}
	for _, domain := range []string{"", "localhost", "127.0.0.1", "::1", "*.example.com", "Mesh.example.com", "mesh.example.com.", "a..example.com", "-a.example.com", "a-.example.com", "a_b.example.com", "a\n.example.com", strings.Repeat("a", 64) + ".example.com", longest + "e"} {
		if ValidDomain(domain) {
			t.Errorf("invalid public hostname accepted: %q", domain)
		}
		c := services()
		c.Apps = []string{domain}
		if _, err := GenerateServices(c); err == nil {
			t.Errorf("invalid hostname reached gateway configuration: %q", domain)
		}
	}
}
