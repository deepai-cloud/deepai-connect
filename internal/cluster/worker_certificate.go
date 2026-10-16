package cluster

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/deepai-cloud/deepai-connect/internal/platform"
)

// K3s v1.36.4+k3s1 can issue the kubelet client certificate before its Node
// exists. If initial startup is interrupted, certificate authentication fails
// and K3s retries the CSR with an already-consumed HTTP body instead of using
// the bootstrap token. An unfinished worker with a renewed token can recover by
// obtaining a new PUBLIC certificate for its existing private key. This never
// changes the node password, any private key, or a completed installation.
// See upstream pkg/agent/config/config.go, getNodeNamedCrt.
func (m *Manager) preparePendingWorkerCertificate(ctx context.Context) error {
	if m.Config.Role != "worker" || m.Joined || !m.restartPending {
		return nil
	}
	path := filepath.Join(m.Config.DataDir, "k3s", "agent", "client-kubelet.crt")
	certificate, err := platform.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err = validatePendingWorkerCertificate(certificate, m.Config.Name); err != nil {
		return err
	}
	key, err := platform.ReadFile(filepath.Join(filepath.Dir(path), "client-kubelet.key"))
	if err != nil {
		return errors.New("restore the original kubelet private key before resuming this worker")
	}
	if _, err = tls.X509KeyPair(certificate, key); err != nil {
		return errors.New("pending kubelet certificate does not match its original private key")
	}
	// Stop synchronously before touching the certificate so a concurrent K3s
	// bootstrap attempt cannot rewrite it or load it during recovery.
	if _, err = m.Runner.Run(ctx, nil, "systemctl", "stop", UnitName); err != nil {
		return err
	}
	certificate, err = platform.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err = validatePendingWorkerCertificate(certificate, m.Config.Name); err != nil {
		return err
	}
	backup := fmt.Sprintf("%s.connect-pending-%x", path, sha256.Sum256(certificate))
	if err = platform.WriteFile(backup, certificate, true); errors.Is(err, os.ErrExist) {
		// A crash may leave the backup committed before the active certificate
		// is removed. Reuse only the identical certificate, never overwrite it.
		prior, readErr := platform.ReadFile(backup)
		if readErr != nil || !bytes.Equal(prior, certificate) {
			return errors.New("pending kubelet certificate backup conflicts with local state")
		}
	} else if err != nil {
		return err
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	return root.Remove(filepath.Base(path))
}

func validatePendingWorkerCertificate(raw []byte, name string) error {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("pending kubelet certificate is invalid; explicit recovery required")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || certificate.Subject.CommonName != "system:node:"+name || !slices.Contains(certificate.Subject.Organization, "system:nodes") {
		return errors.New("pending kubelet certificate belongs to another identity; explicit recovery required")
	}
	return nil
}
