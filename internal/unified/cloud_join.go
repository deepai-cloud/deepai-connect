package unified

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/deepai-cloud/deepai-connect/internal/cloudconfig"
	"github.com/deepai-cloud/deepai-connect/internal/enrollment"
	"github.com/deepai-cloud/deepai-connect/internal/platform"
)

// Named invitations carry the declared public endpoint for joining hubs.
// These bootstrap hints are checked again against the authenticated grant.
func namedJoinOptions(inv *enrollment.Invitation, name, ip, relay *string) error {
	if inv.Name == "" {
		return nil
	}
	for _, pair := range []struct {
		flag     string
		value    *string
		expected string
	}{{"name", name, inv.Name}, {"public-ip", ip, inv.PublicIP}, {"relay-domain", relay, inv.RelayDomain}} {
		if *pair.value != "" && *pair.value != pair.expected {
			return fmt.Errorf("--%s differs from the named invitation", pair.flag)
		}
		*pair.value = pair.expected
	}
	return nil
}

// Do not embed bytes.Buffer: its promoted ReadFrom would let io.Copy (including
// exec.Cmd's stdout copier) bypass the size check in Write.
type invitationBuffer struct{ buffer bytes.Buffer }

func (b *invitationBuffer) Bytes() []byte { return b.buffer.Bytes() }

func (b *invitationBuffer) Write(p []byte) (int, error) {
	if b.buffer.Len()+len(p) > 64<<10 {
		return 0, errors.New("invitation response exceeds 64 KiB")
	}
	return b.buffer.Write(p)
}

func enrollCloudRemote(ctx context.Context, file, name, out, dir string, ttl time.Duration) error {
	if name == "" || out == "" || out == "-" {
		return errors.New("enroll -f requires --node NAME and --out FILE (a private local file)")
	}
	if ttl <= 0 || ttl > 24*time.Hour {
		return errors.New("invitation lifetime must be between zero and 24h")
	}
	if _, err := os.Lstat(out); err == nil {
		return errors.New("invitation output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := platform.CheckPath(out); err != nil {
		return err
	}
	c, err := cloudconfig.Load(file)
	if err != nil {
		return err
	}
	n, ok := c.Nodes[name]
	if !ok {
		return fmt.Errorf("node %q is not declared", name)
	}
	hub := c.Nodes[c.Bootstrap.Node].Connection.SSH
	if hub == "" {
		return errors.New("declare the bootstrap hub connection.ssh, or run enroll --node directly on the hub")
	}
	args, err := cloudSSHArgs(hub, "deepai-connect", "enroll", "--node", name, "--out", "-", "--dir", dir, "--ttl", ttl.String())
	if err != nil {
		return err
	}
	var response invitationBuffer
	if err = cloudProcess(ctx, args, nil, &response, os.Stderr); err != nil {
		return err
	}
	var inv enrollment.Invitation
	decoder := json.NewDecoder(bytes.NewReader(response.Bytes()))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&inv) != nil || decoder.Decode(new(any)) != io.EOF || inv.Version != 1 || inv.ClusterID == "" ||
		inv.Name != name || inv.Role != n.Role || inv.Voter != n.Voter || inv.PublicIP != n.PublicIP ||
		inv.RelayDomain != n.RelayDomain || inv.URL != "https://"+c.Network.Domain ||
		len(inv.Token) != 68 || !strings.HasPrefix(inv.Token, "dai-") || !time.Now().Before(inv.Expires) {
		return errors.New("hub returned an invitation inconsistent with cloud.yaml; apply the manifest first")
	}
	if _, err = hex.DecodeString(inv.Token[4:]); err != nil {
		return errors.New("hub returned an invalid invitation token")
	}
	if err = writeJSON(out, inv, true); err != nil {
		return err
	}
	fmt.Printf("One-use invitation for %s saved to %s. Transfer it privately and run deepai-connect join --invite FILE on the device.\n", name, out)
	return nil
}

// Cloud administration can run on the laptop. Ordinary host lifecycle commands
// retain their Linux guard, including enroll without an explicit cloud file.
func PortableCommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	if args[0] == "plan" || args[0] == "apply" {
		return true
	}
	if args[0] == "enroll" {
		for _, arg := range args[1:] {
			if arg == "--" {
				break
			}
			if arg == "-f" || arg == "--file" || strings.HasPrefix(arg, "-f=") || strings.HasPrefix(arg, "--file=") {
				return true
			}
		}
	}
	return false
}
