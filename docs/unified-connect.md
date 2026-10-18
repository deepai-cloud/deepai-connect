# DeepAI Connect operating guide

Start with the README's [hub initialization](../README.md#initialize-the-hub) and
[worker joining](../README.md#join-a-worker-node). This guide covers preparation
and ongoing operations.

## Requirements

Hubs and workers need Linux amd64/arm64, root, systemd, `/dev/net/tun`, iproute2,
iptables and sysctl. Mac workers use a Linux VM; Windows worker VMs are unvalidated.
Use the same Connect version on all nodes. The Linux agent includes the mesh engine.

On Ubuntu/Debian:

```sh
sudo apt-get install -y ca-certificates curl iproute2 iptables procps
```

### Install Connect

Download the matching Linux binary, `SHA256SUMS` and `install.sh` from the same
[release](https://github.com/deepai-cloud/deepai-connect/releases). From that directory:

```sh
sudo sh install.sh --from-dir . --bin-dir /usr/local/bin --no-path
deepai-connect version
```

Keep the installed path: systemd records it. For laptop installation, see the
[README](../README.md#install-and-use-from-your-terminal).

### Install K3s

Install the verified **v1.36.4+k3s1** executable on every node. Connect creates
its K3s service; do not start a separate K3s installation.

```sh
(
  set -eu
  test "$(uname -s)" = Linux
  case "$(uname -m)" in
    x86_64) arch=amd64; asset=k3s ;;
    aarch64|arm64) arch=arm64; asset=k3s-arm64 ;;
    *) echo 'Linux amd64 or arm64 is required' >&2; exit 1 ;;
  esac
  download_dir=$(mktemp -d)
  trap 'rm -rf "$download_dir"' EXIT
  cd "$download_dir"
  base=https://github.com/k3s-io/k3s/releases/download/v1.36.4%2Bk3s1
  curl -fL --retry 3 -o "$asset" "$base/$asset"
  curl -fL --retry 3 -o SHA256SUMS "$base/sha256sum-$arch.txt"
  sha256sum --check --ignore-missing SHA256SUMS
  sudo install -m 0755 "$asset" /usr/local/bin/k3s
  /usr/local/bin/k3s --version
)
```

### Build the service image

The release pipeline publishes binaries. From the `deepai-connect` source checkout
at that same version, build and push the image using your registry and release tag:

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  --build-arg VERSION=VERSION \
  -t registry.example.com/deepai-connect:VERSION --push .
```

Nodes must be able to pull this image; configure registry authentication if needed.

### DNS, TLS and firewall

Before initializing the hub:

- Point `mesh.example.com` and `relay-1.example.com` to its public IPv4 address.
- Provide a trusted TLS certificate chain and private key covering the mesh,
  relay and application hostnames. All hubs share this certificate; include
  future relay names or use a suitable wildcard. Connect does not issue certificates.
- Allow TCP 80/443 and UDP 3478/41641 to hubs. Workers need outbound access;
  reachable UDP 41641 improves direct connectivity.
- Keep Kubernetes API 6443, etcd 2379/2380 and Flannel 8472 private.

Default ranges are `100.64.0.0/10` for hosts, `10.42.0.0/16` for pods and
`10.43.0.0/16` for Services. Choose non-overlapping ranges with `create` flags if
these conflict with your network; the host range must stay inside `100.64.0.0/10`.

## Create, join and resume

Follow the [quick start](../README.md#initialize-the-hub) after completing the
requirements above. `create` initializes only the first hub; `enroll` issues an
invitation, and `join` adds a new machine. Use a unique lowercase node name.

Each invitation is private, valid for one machine, and expires after one hour
(`--ttl` allows up to 24 hours). Transfer it over SSH or another private channel.
If an unused invitation expires, issue a fresh one. Remove transferred invitation
copies after successful enrollment; preserve each machine's saved identity.

`create` and `join` wait for readiness; worker startup may take ten minutes.
After an interrupted installation, fix the reported cause and resume on that
same machine, account and state directory:

```sh
sudo deepai-connect resume
sudo deepai-connect inspect
journalctl -u deepai-connect-agent -u deepai-connect-k3s
```

State defaults to `/var/lib/deepai-connect`; use the same `--dir` if overridden.
Do not delete state or rerun `create`/`join` to recover an existing machine.

### Add another hub

The first hub starts alone; the default target is three etcd voters (`--voters 5`
selects five). Add voting hubs one at a time, preparing binaries, DNS and firewall
as above. A single hub remains a single point of failure.

```sh
# On an existing hub; privately transfer the invitation to hub-2.
sudo deepai-connect enroll --role hub --voter --out /root/hub-2.invite

# On the new hub; use its public IPv4 and unique relay hostname.
sudo deepai-connect join --name hub-2 --invite /root/hub-2.invite \
  --public-ip 203.0.113.11 --relay-domain relay-2.example.com
sudo deepai-connect inspect
```

Repeat with a fresh invitation for hub-3. Omit `--voter` to add a control-plane hub
without an etcd vote. A failed voter join keeps its reservation; recover it with
its original state before adding another. Maintain direct UDP paths between hubs
so control-plane recovery does not depend entirely on relays.

## Laptop administration

The Linux/macOS/Windows CLI uses OpenSSH key/agent authentication. The hub account
must be root or have passwordless sudo. `setup` saves access metadata in
`~/.config/deepai-connect/client.json` (`%USERPROFILE%\.config\deepai-connect\client.json`
on Windows); it does not join the laptop to the mesh.

```sh
deepai-connect setup --hub USER@HOST
deepai-connect doctor
deepai-connect nodes
deepai-connect containers -n my-app
deepai-connect logs deployment/my-app -n my-app --tail=100
```

Add `--vm NAME` to setup to include an existing Multipass VM in status checks.
`deepai-connect kubectl ARGS...` runs on the hub, including its file paths and
port-forward listeners. For local files and port forwarding, install local
`kubectl` and use the API tunnel:

```sh
deepai-connect kubeconfig install
deepai-connect tunnel
# In another terminal:
kubectl --context deepai-connect get nodes
```

The tunnel binds localhost port 16443 and verifies the hub's TLS certificate.
Existing contexts and the current selection are preserved; `--set-current`
explicitly switches context. `kubeconfig export --out FILE` writes a separate
file. Use `--direct` only with working private routes to the hub, without a tunnel.
Kubeconfigs contain administrator credentials and are stored with private permissions.

## Native clients and workload routing

Install Tailscale only when the laptop needs direct private IP access:
[macOS](https://tailscale.com/docs/install/mac),
[Windows](https://tailscale.com/docs/install/windows),
[Linux](https://tailscale.com/docs/install/linux).
SSH administration needs no Tailscale app. A native client does not become a worker.
Upstream interoperability tests use Tailscale v1.102.4; native app versions need
connectivity checks after installation or upgrades.

On the hub, create a client key and transfer it privately to the laptop:

```sh
sudo deepai-connect enroll --role client --out /root/client.key
```

Use the hub's coordination URL and key below. The key permits one enrollment
within one hour; no Tailscale-hosted account is required. Start the Tailscale app
and approve its OS network setup first.

macOS:

```sh
/Applications/Tailscale.app/Contents/MacOS/Tailscale up \
  --login-server=https://mesh.example.com \
  --auth-key="file:$HOME/Downloads/client.key" --accept-routes
```

Windows, in elevated PowerShell:

```powershell
& "$env:ProgramFiles\Tailscale\tailscale.exe" up `
  --login-server=https://mesh.example.com `
  --auth-key="file:$env:USERPROFILE\Downloads\client.key" --accept-routes
```

Linux, with `tailscaled` running:

```sh
sudo tailscale up --login-server=https://mesh.example.com \
  --auth-key=file:/absolute/path/client.key --accept-routes
```

Changing the control server changes the active mesh; preserve existing options
if prompted. Check `status`, `ip -4` and `ping HUB_OVERLAY_IP` with the same
Tailscale executable, using the address from `deepai-connect inspect` on the hub.
Remove key copies after registration; retain the client's saved identity.

Traffic uses direct encrypted paths where possible and DERP relays otherwise.
`--accept-routes` enables approved pod/Service routes, not Internet egress.
Connect sends no mesh DNS settings; use IPs for initial application checks.

### Route and packet policy

Nodes advertise their pod ranges; hubs also route pod and Service ranges.
Initial policy permits private host/workload communication. Replace it with
`sudo deepai-connect policy --file policy.json`, using an array of upstream
`tailcfg.FilterRule` objects. An empty array denies traffic; retain the paths
needed for Kubernetes and enrollment.

Additional subnet routes must be advertised by the native router and approved:

```sh
sudo deepai-connect route --node router-1 --cidr 192.168.20.0/24
# Withdraw approval:
sudo deepai-connect route --node router-1 --cidr 192.168.20.0/24 --revoke
```

Route approval and packet policy are separate. Kubernetes NetworkPolicy still
applies, but Service NAT and node-origin exceptions can hide client identity;
use coordinator policy where original client restrictions are required.

## Public ingress and optional Internet egress

Deploy a workload and Kubernetes Service, point its hostname to the hub and
ensure the gateway certificate covers it. On the hub:

```sh
sudo deepai-connect publish --hostname app.example.com \
  --service default/my-app --port 8080
```

Traffic follows HTTPS → Caddy → Traefik → Service. Applications need their own
authentication. Repeating `publish` updates the backend within its namespace;
remove the old HTTPRoute before moving that hostname to another namespace.

`publish` creates a Gateway API v1 HTTPRoute attached to
`deepai-system/connect-public`. K3s must include the standard Gateway API CRDs
and a compatible Traefik v3 chart (the pinned K3s release includes both). Connect
enables the provider through `kube-system/traefik` HelmChartConfig, preserving
unrelated chart values. It keeps Traefik internal as a ClusterIP Service; Caddy
terminates public TLS and reaches its HTTP entrypoint through Service port 80.
Only namespaces labeled `connect.deepai.cloud/publish=true` can attach routes;
`publish` adds this label after checking hostname ownership. Treat permission
to edit these namespaces and their HTTPRoutes as publication authority.

Proxy headers are trusted only from protected hub node IPs and the first address
of each hub PodCIDR (the K3s CNI bridge). Reconciliation refreshes this list and
removes retired addresses. This assumes the bundled K3s Flannel networking;
custom CNIs need their proxy source behavior verified. Caddy overwrites client
forwarding headers and retries application proxy connection failures for within
a five-second retry window, with 100 ms intervals. Caddy’s default GET-only matching
limits retries after an upstream round trip has begun; POST requests are not
replayed after such failures. These retries do not eliminate single-hub outages.

After upgrading, run `resume`, then repeat `publish` for each existing simple
Connect-generated Ingress. The old Ingress is deleted only after the HTTPRoute
reports Accepted and ResolvedRefs for its current generation. A failure leaves
the old Ingress in place; fix the cause and retry. Customized Ingresses and
competing hostname claims require an explicit operator migration. Foreign
routes are never deleted. Existing Ingresses continue working through Traefik
during the transition. DNS and a certificate covering every published hostname
remain prerequisites; wildcard DNS alone does not supply a wildcard certificate.
Certificate rotation requires updating the TLS Secret and rolling out the gateway.

To offer optional Internet egress, run on a hub:

```sh
sudo deepai-connect gateway --interface eth0
```

Then opt in on a worker, using that worker's actual pod prefix:

```sh
sudo deepai-connect egress --source 10.42.2.0/24
```

This restarts the worker's network/K3s services. Selected sources use the gateway;
the host's existing default route stays intact. An unreachable route blocks those
sources if all gateways disappear. A hub's upstream Internet outage requires
withdrawing its gateway approval; agent health alone cannot detect it.

Disable on the corresponding worker and hub:

```sh
sudo deepai-connect egress --disable
sudo deepai-connect gateway --disable
```

Interrupted cleanup resumes from saved state. Ordinary agent stops retain the
unreachable guard. Gateway disable preserves shared packet policy; update that
separately with `policy --file` if needed.

## Durable state and recovery

Back up `/var/lib/deepai-connect`, the K3s server token and etcd snapshots together.
The token is needed to decrypt bootstrap data. Application volumes need their
own backups and redundancy. Follow [K3s restore instructions](https://docs.k3s.io/cli/etcd-snapshot)
before resuming original hosts; never replace identities to bypass recovery.

The agent restores saved mesh paths before K3s, independently of the coordinator.
Cached trust expires after 30 days without authenticated synchronization. If only
the local snapshot expired, refresh through a reachable coordinator:

```sh
sudo systemctl stop deepai-connect-k3s.service deepai-connect-agent.service
sudo deepai-connect refresh --dir /var/lib/deepai-connect
sudo deepai-connect resume --dir /var/lib/deepai-connect
```

Refresh requires the original identity, valid membership and trusted HTTPS.
It cannot repair revoked/expired keys or an unavailable coordinator. Restore
control-plane availability first when necessary. Losing etcd quorum blocks
control changes even while cached packet forwarding continues.

See [architecture](architecture.md) for recovery boundaries and
[acceptance tests](testing-unified.md) for failure validation. Multiple hubs alone
do not establish cross-region HA or guarantee uninterrupted application connections.
