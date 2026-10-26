# DeepAI Connect operating guide

Start with the README's [hub initialization](../README.md#initialize-the-hub) and
[worker joining](../README.md#join-a-worker-node). This guide covers preparation
and ongoing operations.

For CLI installation, on-demand VM/host start and stop, explicit login/boot
preferences and safe CLI rollback/uninstall, use the
[lifecycle guide](lifecycle.md). It includes the current platform support matrix
and [agent workflow](../.agents/skills/deepai-connect-lifecycle/SKILL.md).

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

For a version-controlled network and node inventory, follow
[cloud configuration as code](cloud-as-code.md). `plan` and `apply` use the
bootstrap hub's optional SSH connection; named invitations let devices join
without SSH. Once a cloud is applied, use `enroll --node NAME` for declared hubs
and workers; their role and voter permissions come from the manifest.

Each invitation is private, valid for one machine, and expires after one hour
(`--ttl` allows up to 24 hours). Transfer it over SSH or another private channel.
If an unused invitation expires, issue a fresh one. Remove transferred invitation
copies after successful enrollment; preserve each machine's saved identity.

Declared nodes pull their configuration automatically. On a Linux node,
`sudo deepai-connect pull --json` fetches and displays its latest configuration.
This does not replace the cached mesh state used for independent recovery.

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

## Node resources

```sh
deepai-connect nodes
deepai-connect nodes --details
deepai-connect nodes --json
```

The default output is a single table, like `kubectl get nodes`:

```text
NAME          STATUS  CPU  CPU%  MEMORY  MEM%  DISK     DISK%
hub-1         Ready   2    4%    7.75Gi  28%   95.85Gi  6%
mac-worker-1  Ready   2    2%    2.89Gi  19%   6.71Gi   50%
```

Values above are illustrative. CPU and memory are total node capacities; disk is
the measured local filesystem capacity. Percentages show sampled usage divided
by those capacities. Missing or stale usage appears as `<unknown>`, including
when a sample has no timestamp or is over five minutes old.

Use `--details` for the complete breakdown and diagnostics, or `--json` for the
structured report. For native Kubernetes output, use
`deepai-connect kubectl get nodes -o wide` (or `-o json`).

The detailed report separates three measurements:

- **Capacity:** the CPU and memory visible to Linux on each node. A Mac worker
  reports its Linux VM, not the whole Mac.
- **Allocatable:** the Kubernetes budget for pods after configured system
  reservations and eviction thresholds. This is not unused capacity: existing
  pods also consume this budget.
- **Usage:** sampled CPU, memory working set and local filesystem usage. Missing
  metrics remain unavailable, not zero. An unreachable node can retain its last
  reported capacity in Kubernetes.

Local disk space belongs to each node. Current filesystem measurements can differ
from the capacity last advertised by a kubelet, especially after a disk resize.
Persistent volumes and claims are reported separately; neither their sizes nor
the sum of node disks represents a shared storage pool.

## Worker resource grants

The worker VM is the boundary between a Mac and the cluster. Detect the computer's
CPU count, total RAM and available space on the reported host filesystem, and
compare these with its configured VM grant:

```sh
deepai-connect setup --hub USER@HOST --vm EXISTING_VM
deepai-connect vm resources
deepai-connect vm resources --name EXISTING_VM --json
```

VM settings are read from Multipass even when guest SSH or K3s is unavailable.
The host filesystem being checked is identified in the output: Multipass may keep
its VM images on a different volume. Other VMs and host applications also need
resources, so total host capacity is not a promise that it is all currently free.

Specify the grant before creating a VM, then install the prerequisites and join
that VM using the existing worker installation steps:

```sh
# Preview only. Choose sizes that fit your computer and leave host headroom.
deepai-connect vm create --name my-worker --cpus 4 --memory 8GiB --disk 32GiB
# Repeat with --apply to create the VM with those limits.
```

For an existing VM, preview an explicit new grant:

```sh
deepai-connect vm configure --name EXISTING_VM --cpus 4 --memory 8GiB --disk 32GiB
```

Applying a resize requires a stopped VM and interrupts its workloads. Schedule
the interruption or drain the Kubernetes node according to its workload policy,
then stop the VM with `multipass stop EXISTING_VM`. Repeat `vm configure` with
`--apply`, then run `multipass start EXISTING_VM`. The command preserves the VM
and its device identity; it never stops a running worker automatically. Disk
capacity can grow but cannot shrink. Check `nodes` after startup to confirm
the node and guest filesystem see the new sizes. A failed multi-setting update
may have applied some settings; inspect `vm resources` before retrying.

These grants have specific meanings:

| Resource | What the grant does | What it does not reserve |
| --- | --- | --- |
| CPU | Gives the VM that many virtual CPUs | Exclusive physical cores or guaranteed performance; host workloads still compete |
| Memory | Sets guest RAM capacity, shared by its OS, K3s and pods | RAM for pod workloads alone; hypervisor overhead is additional |
| Disk | Sets the virtual disk's logical capacity | Physical host space in advance; sparse images grow as data is written, and snapshots/metadata can use extra space |

Multipass grants and host capacity checks do not preallocate storage. A guaranteed
disk reservation requires backing storage provisioned for that purpose, with
appropriate preallocation or filesystem reservation and monitoring. Avoid
overcommitting a nearly full host disk. Guest partitions/filesystems may also
need expansion after a virtual disk is enlarged.

On macOS, an [APFS volume reserve](https://support.apple.com/guide/disk-utility/add-delete-or-erase-apfs-volumes-dskua9e6a110/mac)
can guarantee space for the backing volume; a quota limits its growth. Multipass
supports [placing its data on that volume](https://canonical.com/multipass/docs/latest/how-to-guides/customise-multipass/configure-where-multipass-stores-external-data/).
This is a separate storage provisioning/migration operation and can affect all
local Multipass instances. `vm configure` does not create APFS volumes, move
existing images, or claim a physical reservation that has not been provisioned.

Inside the VM, Kubernetes uses **requests** to decide whether a pod fits and to
assign CPU shares under contention. Increasing requests does not enlarge the
VM. **Limits** constrain a workload: CPU is throttled, exceeding a memory limit
can terminate it, and exceeding measured ephemeral storage limits can trigger
eviction. Pods without limits can compete for the remaining node resources.

Connect currently leaves K3s system and kubelet resource reservations at their
defaults; it does not reserve a dedicated CPU or memory margin for the guest OS
and cluster services. Use workload requests/limits and leave room in the VM grant
for those services. On bare Linux nodes the visible machine resources are used
directly; the VM boundary described here applies only to workers running in VMs.

Container writable layers, logs and disk-backed `emptyDir` volumes use local
ephemeral storage. Persistent volume claims are separate: the default
`local-path` provisioner does **not enforce PVC capacity limits**. A PVC requesting
10 GiB therefore does not establish a hard 10 GiB filesystem quota. Use a storage
backend that enforces quotas when per-volume guarantees are required.

References: [Kubernetes requests and limits](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/),
[node reservations](https://kubernetes.io/docs/tasks/administer-cluster/reserve-compute-resources/),
[Multipass resizing](https://canonical.com/multipass/docs/latest/how-to-guides/manage-instances/modify-an-instance/),
[local-path limitations](https://github.com/rancher/local-path-provisioner#cons).

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
