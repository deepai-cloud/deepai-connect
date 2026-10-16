# DeepAI Connect operating guide

DeepAI Connect manages one K3s cluster and private host overlay. `create`
initializes the first hub; `enroll` and `join` add hubs, workers and native
clients. See [architecture](architecture.md) for component and state ownership.

## Laptop administration

Install the native terminal command with `sh install.sh --from-source` from a
checkout, or use the release installer described in the [README](../README.md).
Configure an existing hub with `deepai-connect setup --hub USER@HOST`. The SSH
account needs root or passwordless sudo on the hub; normal SSH host verification
remains enabled. Add `--vm NAME` to include an existing local Multipass VM in
status checks. Setup saves connection metadata in
`~/.config/deepai-connect/client.json`; it does not create or reenroll machines.

```sh
deepai-connect status
deepai-connect doctor
deepai-connect nodes
deepai-connect containers -n my-app
deepai-connect logs deployment/my-app -n my-app --tail=100
deepai-connect kubectl describe pod POD -n my-app
```

Administration uses SSH and the hub's existing Kubernetes credentials. Local
`kubectl` and a native mesh connection are optional. `containers` lists Kubernetes
pods with their container readiness; `logs` accepts normal `kubectl logs` options.
The wrapper executes on the hub, so file paths and port-forward listeners are
remote. Pipe local manifests to `deepai-connect kubectl apply -f -`, or use the
local client below for laptop-local file and port operations.
The health report checks the mesh, system services, API, nodes and infrastructure
pods. It cannot establish application availability or independent etcd quorum.

To use an installed local `kubectl`, install a separate context and run the API
tunnel in another terminal:

```sh
deepai-connect kubeconfig install
deepai-connect tunnel
# In another terminal:
kubectl --context deepai-connect get nodes
```

The default context uses `https://127.0.0.1:16443` and verifies the certificate
against the hub's overlay address. The tunnel binds only to localhost and runs
until interrupted. Existing contexts and the current context are preserved;
use `--set-current` only when you want to switch. Kubeconfigs contain privileged
credentials and are written with mode `0600`.

`deepai-connect kubeconfig export --out FILE` saves a separate configuration.
Use `--direct` when the laptop already has a working route to the hub's private
overlay API; a direct context does not require the SSH tunnel. These commands
do not install a VPN or change host routes.

## Requirements

Hubs and workers run on Linux amd64 or arm64 with systemd, root access, `/dev/net/tun`,
`ip` (iproute2), `iptables`, and `sysctl`. Install the verified
**K3s v1.36.4+k3s1** executable at `/usr/local/bin/k3s`. Connect checks the version;
it does not download or execute a remote installer. A worker on macOS runs inside
a Linux VM. The macOS host itself needs a native Tailscale client or explicit
routes to join the network.

### Install K3s

On each Linux host, download the binary and matching checksum from the pinned
[official K3s release](https://github.com/k3s-io/k3s/releases/tag/v1.36.4%2Bk3s1):

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

Connect creates the K3s systemd service itself; installing this executable does
not start a second K3s instance. On Ubuntu/Debian, the host utilities can be
installed with `sudo apt-get install -y ca-certificates curl iproute2 iptables
procps`. Enable `/dev/net/tun` and use a systemd-based Linux host or VM.

### Build and install Connect

Build/install the Connect executable and build its service image:

```sh
go run ./cmd/release -version connect-dev
docker buildx build --platform linux/amd64,linux/arm64 \
  --build-arg VERSION=connect-dev \
  -t registry.example.com/deepai-connect:connect-dev --push .
```

Use your own registry and a release tag or immutable digest; configure image-pull
authentication when needed. Copy the matching Linux binary to
`/usr/local/bin/deepai-connect` on each host. Keep that path: systemd records it.

### DNS, certificates and firewall

Prepare a publicly trusted certificate chain and private key covering the shared
coordination domain, every relay hostname and every application hostname. A
wildcard for `*.example.com` can cover the example names below. The key is stored
in the private bootstrap directory and a Kubernetes TLS Secret. All hubs use
that Secret, avoiding per-hub ACME challenges on a shared DNS name. Private CAs
work only when every connecting client trusts them.

Create DNS records for `mesh.example.com` and individual relay names. Shared mesh
and application hostnames can resolve to multiple hubs or a health-aware external
load balancer; each relay hostname must reach its own hub. Connect reconciles
private route failover; it does not administer your DNS provider or move a public
IP address. Public load-balancer health checks should use `/readyz`.

Allow TCP 80/443 and UDP 3478/41641 to hubs. Workers require outbound access and
benefit from reachable UDP 41641. Kubernetes API 6443, etcd 2379/2380 and Flannel
8472 traffic use overlay addresses; do not expose them publicly. Existing host
firewall and CNI rules remain installed. Connect adds only its own chains, routes
and explicitly configured egress rules.

Connect restricts local UDP8472 delivery to overlay ingress before starting
K3s. These guards remain after agent shutdown because CNI containers may survive.

## Create, join and resume

On the first Linux hub:

```sh
sudo deepai-connect create --name hub-1 \
  --domain mesh.example.com --public-ip 203.0.113.10 \
  --relay-domain relay-1.example.com \
  --image registry.example.com/deepai-connect:connect-dev \
  --tls-cert /root/fullchain.pem --tls-key /root/privkey.pem \
  --voters 3
```

Replace the documentation addresses with reachable public addresses. The first
hub starts alone, with embedded etcd. Add two more voting hubs to reach three,
or four more when `--voters 5` was selected. Add voters **one at a time**:

```sh
# On an established hub; transfer this file privately to exactly one new hub.
sudo deepai-connect enroll --role hub --voter --out /root/hub-2.invite

# On the new hub, after installing the same Connect and K3s binaries.
sudo deepai-connect join --name hub-2 --invite /root/hub-2.invite \
  --public-ip 203.0.113.11 --relay-domain relay-2.example.com
```

Repeat with a fresh invitation for hub-3. Omitting `--voter` authorizes an
additional control-plane hub with `--disable-etcd`; it still provides coordination,
DERP and ingress without enlarging the etcd quorum. A voting invitation cannot
be used by a worker. Admission reserves one pending voter and verifies cluster
health before proceeding. A failed pending join remains reserved; recover that
host with its original private state instead of deleting the reservation or
admitting another voter.

For workers:

```sh
# Established hub
sudo deepai-connect enroll --role worker --out /root/worker.invite

# Linux worker or Linux VM
sudo deepai-connect join --name worker-1 --invite /root/worker.invite
```

Invitations expire after one hour (`--ttl` supports up to 24 hours) and bind to
one machine and signing key. An expired unclaimed invitation needs a fresh file;
saved claims resume with the original identity. A signed overlay challenge
precedes credential release. Workers receive expiring bootstrap tokens; hubs
receive the privileged server token.

For an unfinished worker join, `resume` can renew the bootstrap token and
archive an uncommitted public `client-kubelet.crt` to request a replacement.
It preserves the cluster CA, configuration, node password and private keys.
Completed workers keep their credentials. Readiness waits for the K3s systemd
service as well as the Node; initial startup can take up to ten minutes.

All host commands default to `/var/lib/deepai-connect`; `--dir` selects a
different private directory. Resume under the same account and directory:

```sh
sudo deepai-connect resume
sudo deepai-connect inspect
journalctl -u deepai-connect-agent -u deepai-connect-k3s
```

For Kubernetes administration on a hub, use its private kubeconfig and actual
overlay address (replace `HUB_OVERLAY_IP`):

```sh
sudo k3s kubectl --kubeconfig /var/lib/deepai-connect/cluster/kubeconfig \
  --server=https://HUB_OVERLAY_IP:6443 get nodes -o wide
```

The host agent restores saved identities, policies and direct hub endpoints
before K3s, independently of the Kubernetes API, cluster DNS and relays. Cached
trust expires after 30 days without authenticated synchronization. Expired peer
keys/endpoints are removed; an expired local key or snapshot prevents startup.
Do not extend cache timestamps or replace identities to bypass recovery checks.

Keep direct UDP paths between the hubs reachable. A client behind restrictive
NAT can use another relay while the coordinator remains reachable. If every hub
depends on the same relay and that relay fails, the coordinator's own cluster
network can also become unavailable, preventing distribution of changed relay
locations. Multiple relays do not replace the direct hub paths required for
independent control-plane recovery.

If only the local snapshot expired, refresh it through the current coordinator
using the original machine and node identity:

```sh
sudo systemctl stop deepai-connect-k3s.service deepai-connect-agent.service
sudo deepai-connect refresh --dir /var/lib/deepai-connect
sudo deepai-connect resume --dir /var/lib/deepai-connect
```

`refresh` requires the stopped agent, original identity, valid HTTPS and a fresh
authenticated network map. Revoked/expired membership, bad TLS, unavailable
control or inconsistent identity leaves the cache unchanged. If the coordinator
is unavailable, restore it through still-valid hosts or cluster backup first;
an expired cache cannot provide offline recovery.

## Native clients and workload routing

Upstream Tailscale **v1.102.4** is the tested client version. On a hub:

```sh
sudo deepai-connect enroll --role client --out /root/client.key
```

Transfer that file privately and register a native client:

```sh
sudo tailscale up --login-server=https://mesh.example.com \
  --auth-key=file:/absolute/path/client.key --accept-routes
```

The default ranges are `100.64.0.0/10` for hosts, `10.42.0.0/16` for pods, and
`10.43.0.0/16` for Services. Creation flags can choose distinct ranges; the host
range must remain inside `100.64.0.0/10`. Each node advertises its assigned pod
prefix after Kubernetes identity/readiness checks. Hubs also advertise pod and Service
routes; a deterministic healthy router is selected, with stale candidates
removed after 90 seconds. CNI routes retain their ownership and carry node traffic
over `deepai0`. This is routed connectivity, not a shared Layer-2 network.

Initial policy permits communication between private hosts and workload ranges.
Replace it with a JSON array of upstream `tailcfg.FilterRule` objects using
`deepai-connect policy --file policy.json`. An empty array denies packet traffic.
Keep the paths required by Kubernetes and enrollment when tightening policy.
Additional subnet routes require both advertisement and explicit approval:

```sh
sudo deepai-connect route --node router-1 --cidr 192.168.20.0/24
sudo deepai-connect route --node router-1 --cidr 192.168.20.0/24 --revoke
```

Native clients advertise subnet routes with their upstream options. Managed
hosts accept only their configured pod/Service ranges and explicit egress opt-in.
Route approval is independent of the packet policy.

Kubernetes NetworkPolicy still governs forwarded pod traffic. Test a direct pod
address from another host when validating ingress restrictions. Service routing
can translate the original source address through kube-proxy, and Kubernetes
policies exempt some node-origin traffic; an overlay identity is not guaranteed
to remain visible behind every Service path. Coordinator packet policy can also
restrict the original client and Service destination before that translation.

## Public ingress and optional Internet egress

Deploy a workload and Kubernetes Service, then publish its HTTP port:

```sh
sudo deepai-connect publish --hostname app.example.com \
  --service default/my-app --port 8080
```

The hostname must be covered by the shared gateway certificate. Connect creates
a Traefik Ingress and reconciles the Caddy gateway configuration across hubs.
Publishing the same hostname again updates its backend within that namespace.
Moving it to another namespace requires explicitly removing the old Ingress;
Connect rejects competing routes for the same hostname.
Traffic is HTTPS → Caddy → Traefik → Service. The application still needs its own
authentication. Gateway updates use controlled Kubernetes rollouts; existing TCP
connections and application-volume replication are not guaranteed to survive
hub failure. Certificate rotation remains an explicit Kubernetes Secret update
and gateway rollout; retain the old key/certificate until verified.

CoreDNS and Traefik run at least two replicas on hubs, spread when possible.
Lifecycle commands wait for readiness; the coordinator repairs placement and
replica count every 30 seconds. Node detection, endpoint removal, DNS retries
and route selection can interrupt connections during failover.

Offer optional Internet egress on one or more hubs:

```sh
sudo deepai-connect gateway --interface eth0
```

This explicitly authorizes Internet destinations, advertises an approved default
route and installs SNAT scoped to the cluster host/pod sources. On a consuming
worker, opt a local pod prefix into the selected gateway:

```sh
sudo deepai-connect egress --source 10.42.2.0/24
```

Use the worker's actual pod prefix. The command restarts its network/K3s
services. Selected sources use table 186; the physical default and private
host/pod/Service paths stay intact. An unreachable fallback blocks those sources
if all gateways disappear. Internet pod traffic is translated to the worker's
overlay address before WireGuard. The shared public-IPv4 policy grant excludes
private, cluster and reserved ranges, preserving private-network ACLs.

Gateway and consumer roles are distinct; DERP only relays encrypted packets.
Route health follows the agent heartbeat, so an upstream Internet outage on a
running gateway requires withdrawal of its default-route approval.

Disable these optional settings with the same installation directory:

```sh
sudo deepai-connect egress --disable
sudo deepai-connect gateway --disable
```

Run each command where its role was enabled. Gateway disable withdraws approval
before removing its SNAT rules; consumer disable restores normal routing.
`resume` or agent startup completes interrupted cleanup from its saved intent.
Ordinary agent stops retain the unreachable guard, preventing surviving pods
from falling back to the uplink. Gateway disable preserves shared packet policy;
change it separately with `policy --file`. Configuration changes cannot extend
cache trust: map-dependent commands need `refresh` after its 30-day expiry.

Direct pod-to-private-host traffic retains its assigned pod source address.
A scoped NAT exemption runs before Flannel masquerade, while Service DNAT/SNAT
and unrelated forwarding retain their normal CNI handling.

## Durable state and recovery

Back up the private host directories, K3s server token and etcd snapshots together.
Use K3s's documented snapshot/restore procedure, then resume the original hosts.
The server token is required to decrypt bootstrap data. Losing quorum stops
network control changes and Kubernetes changes together; established encrypted
forwarding can continue using cached state. Missing durable registry state is an
error on resume, not permission to generate replacements. Keep backups private
and never commit credential files or raw Kubernetes Secret exports.

Use `create` once on the first hub and `join` once on each additional host.
Subsequent recovery uses `resume` with that host's original private directory.
Conflicting K3s services or mismatched saved configuration are rejected, so a
mistyped state directory cannot take over another installation.

Protocol and runtime references: [custom Tailscale control servers](https://tailscale.com/docs/how-to/set-up-custom-control-server),
[K3s token security](https://docs.k3s.io/cli/token),
[Kubernetes bootstrap tokens](https://kubernetes.io/docs/reference/access-authn-authz/bootstrap-tokens/),
[K3s multicloud constraints](https://docs.k3s.io/networking/distributed-multicloud).
