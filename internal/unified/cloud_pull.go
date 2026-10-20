package unified

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/coordinator"
	"github.com/deepai-cloud/deepai-connect/internal/enrollment"
	"github.com/deepai-cloud/deepai-connect/internal/hostnet"
	"github.com/deepai-cloud/deepai-connect/internal/platform"
)

type savedNodeConfiguration struct {
	enrollment.NodeConfiguration
	Cluster enrollment.Cluster `json:"cluster"`
}

type configExchange func(context.Context, enrollment.Invitation, ed25519.PrivateKey, coordinator.Node, string) (enrollment.Grant, error)

func pullCommand(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pull", flag.ContinueOnError)
	dir := fs.String("dir", defaultDir, "private installation directory")
	asJSON := fs.Bool("json", false, "print the non-secret configuration after an authenticated pull")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := hostRequired(); err != nil {
		return err
	}
	absolute, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	if err = pullConfiguration(ctx, absolute, enrollment.Exchange); err != nil {
		return err
	}
	raw, err := platform.ReadFile(filepath.Join(absolute, "configuration.json"))
	if errors.Is(err, os.ErrNotExist) {
		fmt.Println("No cloud configuration is declared for this node.")
		return nil
	}
	if err != nil {
		return err
	}
	if *asJSON {
		_, err = os.Stdout.Write(raw)
		return err
	}
	var saved savedNodeConfiguration
	if err = json.Unmarshal(raw, &saved); err != nil {
		return err
	}
	fmt.Printf("Configuration for %s fetched at revision %s.\n", saved.Name, saved.Revision)
	return nil
}

// Pulls do not gate mesh readiness, restart services, rewrite installation
// state, or extend the trust lifetime of the independent network cache.
func runConfigurationPuller(ctx context.Context, dir string, logf func(string, ...any)) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		i, err := loadInstallation(dir)
		if err == nil {
			// Legacy first hubs acquire a signer binding when apply adopts them.
			// The apply path also writes the initial configuration cache.
			_, cached := os.Stat(filepath.Join(dir, "configuration.json"))
			if !i.Config.FirstHub || i.BootstrapCloud != nil || cached == nil {
				err = pullConfiguration(ctx, dir, enrollment.Exchange)
			}
		}
		if err != nil && ctx.Err() == nil {
			logf("cloud configuration pull pending: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func pullConfiguration(ctx context.Context, dir string, exchange configExchange) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	i, err := loadInstallation(dir)
	if err != nil {
		return err
	}
	// Serialize the entire exchange, not just the write: otherwise an older
	// request can finish after a newer pull and roll the cache back.
	unlock, err := platform.Lock(filepath.Join(dir, "configuration-lock"))
	if err != nil {
		return err
	}
	defer unlock()
	id, err := hostnet.LoadIdentity(i.Config.AgentStateDir)
	if err != nil {
		return err
	}
	signer, err := enrollment.LoadIdentity(dir)
	if err != nil {
		return err
	}
	inv := enrollment.Invitation{ClusterID: i.ClusterID, URL: i.Services.PublicURL, Role: i.Config.Role, Voter: i.Config.Voter}
	if i.Invitation != nil {
		inv = *i.Invitation
	}
	node := nodeFor(id, i.Config.Name, i.Config.Role, nil)
	request, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	g, err := exchange(request, inv, signer, node, "config")
	if err != nil {
		return err
	}
	if err = request.Err(); err != nil {
		return err
	}
	if err = enrollment.ValidateGrant(inv, node, g, false); err != nil {
		return err
	}
	return saveGrantedConfigurationLocked(dir, i, g, true)
}

func saveGrantedConfiguration(dir string, i *installation, g enrollment.Grant, installed bool) error {
	// A dedicated lock avoids competing with resume's installation lock while
	// serializing initial enrollment and manual/periodic configuration pulls.
	unlock, err := platform.Lock(filepath.Join(dir, "configuration-lock"))
	if err != nil {
		return err
	}
	defer unlock()
	return saveGrantedConfigurationLocked(dir, i, g, installed)
}

func saveGrantedConfigurationLocked(dir string, i *installation, g enrollment.Grant, installed bool) error {
	if g.Token != "" {
		return errors.New("configuration response unexpectedly contains cluster credentials")
	}
	if g.Configuration == nil {
		_, err := platform.ReadFile(filepath.Join(dir, "configuration.json"))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil || i.BootstrapCloud != nil || (i.Invitation != nil && i.Invitation.Name != "") {
			return errors.New("coordinator omitted this declared node's configuration")
		}
		return nil
	}
	c := g.Configuration
	if c.Name != i.Config.Name || c.Node.Role != i.Config.Role || c.Node.Voter != i.Config.Voter ||
		c.Node.PublicIP != i.PublicIP || c.Node.RelayDomain != i.RelayDomain || c.Node.Connection.SSH != "" ||
		g.Cluster.ID != i.ClusterID {
		return errors.New("pulled configuration differs from local node identity")
	}
	if installed && (g.Cluster.HostCIDR != i.Config.HostCIDR || g.Cluster.PodCIDR != i.Config.PodCIDR ||
		g.Cluster.ServiceCIDR != i.Config.ServiceCIDR || g.Cluster.Image != i.Config.ConnectImage ||
		g.Cluster.DesiredVoters != i.Config.DesiredVoters || g.Self == nil || len(g.Self.Addresses) != 1 ||
		g.Self.Addresses[0].Addr().String() != i.Config.OverlayIP) {
		return errors.New("pulled configuration changes installed cluster parameters; explicit migration is required")
	}
	raw, err := json.MarshalIndent(savedNodeConfiguration{NodeConfiguration: *c, Cluster: g.Cluster}, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	path := filepath.Join(dir, "configuration.json")
	old, err := platform.ReadFile(path)
	if err == nil && bytes.Equal(old, raw) {
		return nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return platform.WriteFile(path, raw, false)
}
