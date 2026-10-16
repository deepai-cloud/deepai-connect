package cluster

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/platform"
)

func partialWorkerCertificate(t *testing.T, m *Manager, name string) (string, []byte, map[string][]byte) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "system:node:" + name, Organization: []string{"system:nodes"}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	agent := filepath.Join(m.Config.DataDir, "k3s", "agent")
	certPath := filepath.Join(agent, "client-kubelet.crt")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err = platform.WriteFile(certPath, certificate, false); err != nil {
		t.Fatal(err)
	}
	untouched := map[string][]byte{
		filepath.Join(agent, "client-kubelet.key"):             pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}),
		filepath.Join(agent, "serving-kubelet.key"):            []byte("serving key must remain unchanged"),
		filepath.Join(agent, "serving-kubelet.crt"):            []byte("serving certificate must remain unchanged"),
		filepath.Join(m.Config.AgentStateDir, "identity.json"): []byte("Connect machine, WireGuard and discovery identities"),
	}
	for path, data := range untouched {
		if err = platform.WriteFile(path, data, false); err != nil {
			t.Fatal(err)
		}
	}
	return certPath, certificate, untouched
}

func TestPendingWorkerCertificateRecoveryPreservesIdentityAcrossInterruptedRestart(t *testing.T) {
	f := &fakeRunner{}
	old := pendingWorker(t, f)
	certPath, original, untouched := partialWorkerCertificate(t, old, old.Config.Name)
	c := old.Config
	c.JoinToken = strings.Replace(c.JoinToken, "1111111111111111", "2222222222222222", 1)
	stops, restarts, joined := 0, 0, false
	f.run = func(_ []byte, command string, args []string) ([]byte, error) {
		arguments := strings.Join(args, " ")
		switch {
		case arguments == "--version":
			return []byte(K3sVersion), nil
		case strings.Contains(arguments, "get node"):
			if !joined {
				return nil, errors.New("Node not yet registered")
			}
			return readyNode(c.OverlayIP), nil
		case command == "systemctl" && strings.HasPrefix(arguments, "stop "):
			stops++
			if raw, err := os.ReadFile(certPath); err != nil || !bytes.Equal(raw, original) {
				t.Fatal("active certificate was changed before K3s stopped")
			}
		case command == "systemctl" && strings.HasPrefix(arguments, "restart "):
			restarts++
			if stops != 1 {
				t.Fatal("K3s was not stopped before retrying partial certificate bootstrap")
			}
			if _, err := os.Stat(certPath); !errors.Is(err, os.ErrNotExist) {
				return nil, errors.New("K3s would authenticate with an unregistered Node certificate and retry an empty CSR body")
			}
			backups, err := filepath.Glob(certPath + ".connect-pending-*")
			if err != nil || len(backups) != 1 {
				t.Fatal("original public certificate was not preserved exactly once")
			}
			backup, err := os.ReadFile(backups[0])
			if err != nil || !bytes.Equal(backup, original) {
				t.Fatal("certificate backup differs from original")
			}
			for path, want := range untouched {
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("recovery changed identity file %s", filepath.Base(path))
				}
			}
			if restarts == 1 {
				return nil, errors.New("interrupted before restart was accepted")
			}
			joined = true
		}
		return nil, nil
	}
	if err := newManager(t, c, f).Install(context.Background()); err == nil {
		t.Fatal("expected interrupted restart")
	}
	resumed, err := Load(c.DataDir, f)
	if err != nil || !resumed.restartPending || resumed.Joined {
		t.Fatal("certificate recovery lost its durable pending-restart journal")
	}
	if err = resumed.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !resumed.Joined || resumed.restartPending || restarts != 2 {
		t.Fatal("worker failed to complete using its original identity")
	}
}

func TestPendingWorkerCertificateRecoveryFailsClosed(t *testing.T) {
	for _, test := range []string{"other-node", "missing-private-key", "symlink-certificate", "stop-failed"} {
		t.Run(test, func(t *testing.T) {
			f := &fakeRunner{}
			m := pendingWorker(t, f)
			name := m.Config.Name
			if test == "other-node" {
				name = "another-worker"
			}
			certPath, certificate, _ := partialWorkerCertificate(t, m, name)
			if test == "missing-private-key" {
				if err := os.Remove(filepath.Join(filepath.Dir(certPath), "client-kubelet.key")); err != nil {
					t.Fatal(err)
				}
			}
			if test == "symlink-certificate" {
				if err := os.Rename(certPath, certPath+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(certPath+".original", certPath); err != nil {
					t.Fatal(err)
				}
			}
			f.run = func(_ []byte, _ string, _ []string) ([]byte, error) {
				if test != "stop-failed" {
					t.Fatal("invalid certificate recovery touched the running service")
				}
				return nil, errors.New("cannot stop K3s")
			}
			m.restartPending = true
			if err := m.preparePendingWorkerCertificate(context.Background()); err == nil {
				t.Fatal("unsafe certificate recovery accepted")
			}
			if got, err := os.ReadFile(certPath); err != nil || !bytes.Equal(got, certificate) {
				t.Fatal("failed recovery modified original certificate")
			}
		})
	}
}

func TestPendingWorkerCertificateRecoverySkipsCompletedOrUnjournaledInstallations(t *testing.T) {
	for _, state := range []string{"completed-worker", "hub", "no-refreshed-token"} {
		t.Run(state, func(t *testing.T) {
			f := &fakeRunner{}
			m := pendingWorker(t, f)
			path, certificate, _ := partialWorkerCertificate(t, m, m.Config.Name)
			m.restartPending = state != "no-refreshed-token"
			m.Joined = state == "completed-worker"
			if state == "hub" {
				m.Config.Role = "hub"
			}
			f.run = func([]byte, string, []string) ([]byte, error) {
				t.Fatal("established or unjournaled installation was stopped")
				return nil, nil
			}
			if err := m.preparePendingWorkerCertificate(context.Background()); err != nil {
				t.Fatal(err)
			}
			if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, certificate) {
				t.Fatal("ineligible installation certificate changed")
			}
		})
	}
}
