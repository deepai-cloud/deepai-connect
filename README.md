# DeepAI Connect

Build a private cloud from your own devices and one public VPS. **One
`deepai-connect` binary manages the encrypted mesh and Kubernetes compute
together:** one Tailscale-compatible network, one K3s cluster. The hub hosts the
coordinator, control plane and public HTTPS ingress; your devices supply compute
while they are online and eligible to run workloads. The design targets
**$10–$20/month for the public hub**, with worker hardware supplied by you.

## How it fits together

- **Networking starts first.** A Linux host agent restores saved mesh identity
  and connectivity before K3s starts. Direct encrypted paths are preferred;
  DERP relays carry encrypted traffic when a direct path is unavailable.
- **Workers run your applications.** Linux machines join as K3s workers; macOS
  supplies compute through a Linux VM with explicit CPU, memory and disk grants.
- **Clients provide private access.** A native Tailscale client can join the mesh
  without becoming a Kubernetes node. CLI administration over SSH is separate
  from mesh enrollment.
- **Publish through the hub.** Selected HTTP services behind home NAT become
  reachable over HTTPS through Caddy → Traefik → Kubernetes Service → workload.
  DNS, a covering TLS certificate and application authentication are still needed.

See the [architecture diagram and component boundaries](docs/architecture.md#topology)
for the traffic paths and [operating guide](docs/unified-connect.md) for setup.
Connect owns networking and compute; shared platform services and the application
UI/orchestration belong to the separate
[platformbase](https://github.com/deepai-cloud/platformbase) and
[App Foundation](https://github.com/deepai-cloud/app-foundation) projects.

## Choose how to connect

| Purpose | Runtime and entry point |
| --- | --- |
| Host the public hub or contribute compute | Linux amd64/arm64; `create` or `join` after [host preparation](docs/unified-connect.md#requirements) |
| Contribute a Mac's compute | A Linux VM; [grant resources](docs/unified-connect.md#worker-resource-grants), prepare the guest and join it as a worker |
| Access private hosts and workloads | A separate native Tailscale client; [client enrollment](docs/unified-connect.md#native-clients-and-workload-routing) |
| Administer the cluster from a laptop | Linux/macOS/Windows CLI and OpenSSH; `setup --hub USER@HOST` |
| Use a published application | Browser or HTTP client; no mesh enrollment required, application access policy applies |

Windows CLI artifacts and native amd64 CLI CI coverage do **not** qualify Windows
worker VMs, native VPN interoperability or automatic startup. See the detailed
[platform support matrix](docs/lifecycle.md#platform-and-verification-boundaries).

## Install and use from your terminal

Download your binary, `SHA256SUMS` and `install.sh` (Mac/Linux) or `install.ps1` (Windows) from
[Releases](https://github.com/deepai-cloud/deepai-connect/releases), or extract the
`deepai-connect-binaries` artifact from [CI](https://github.com/deepai-cloud/deepai-connect/actions/workflows/ci.yml).
Choose `linux`, `darwin` (macOS) or `windows`, and `amd64` (Intel/AMD) or `arm64`.

On macOS/Linux, run from the download directory:

```sh
sh install.sh --from-dir .
```

Open a new terminal after installation.

On Windows, run `.\install.ps1 -FromDir .` in PowerShell and reopen the terminal.
Administration requires OpenSSH. Installing the CLI does not enroll a device or
enable automatic startup. See [installation, rollback and uninstall](docs/lifecycle.md).

## Start and stop your worker

For an existing Mac worker, select its VM once:

```sh
deepai-connect setup --hub USER@HOST --vm EXISTING_VM
deepai-connect vm status --json
deepai-connect vm start
deepai-connect vm stop
```

Stop shuts down the VM and interrupts its workloads. `vm startup enable` and
`vm startup disable` separately control Connect's next-login trigger on macOS;
they do not change the current VM state. Linux hosts use `sudo deepai-connect
host start|stop|status` and `host startup enable|disable|status` for systemd and
machine-boot preferences. Windows worker runtime and automatic startup remain
unqualified. The [lifecycle guide and support matrix](docs/lifecycle.md) explain
the boundaries, prerequisites and structured output.

## Initialize the hub

Hubs and workers require Linux amd64/arm64, systemd, root, `/dev/net/tun`,
iproute2, iptables and **K3s v1.36.4+k3s1**. A Mac worker runs in a Linux VM;
Windows worker VMs remain unvalidated.

Follow [host preparation](docs/unified-connect.md#requirements) to install
Connect at `/usr/local/bin/deepai-connect` and K3s at `/usr/local/bin/k3s`.
Prepare the service image, DNS and TLS certificate before creating the hub.
Replace the example domains and image below; `187.7.75.65` is the POC VPS.

To keep the network and node inventory in Git, use a
[`cloud.yaml` with `plan` and `apply`](docs/cloud-as-code.md). The hub can be
administered over SSH while devices join through named invitations and pull
configuration themselves. See the [example](examples/cloud.yaml).

```sh
# On the VPS
sudo deepai-connect create --name hub-1 \
  --domain mesh.example.com --public-ip 187.7.75.65 \
  --relay-domain relay-1.example.com \
  --image registry.example.com/deepai-connect:VERSION \
  --tls-cert /root/fullchain.pem --tls-key /root/privkey.pem
sudo deepai-connect inspect
```

The first hub starts alone and remains a single point of failure.
[Add voting hubs](docs/unified-connect.md#add-another-hub) later to reach the
default target of three voters; independent-host HA still requires qualification.

## Join a worker node

Install Connect and K3s on the worker using the same host preparation above.
Create a fresh invitation on the hub:

```sh
sudo deepai-connect enroll --role worker --out /root/worker-1.invite
```

Transfer the invitation privately to the Linux worker or Linux VM, then join.
For example, if SSH is available, the transfer can use `scp`:

```sh
umask 077
scp root@187.7.75.65:/root/worker-1.invite .
sudo deepai-connect join --name worker-1 --invite ./worker-1.invite
sudo deepai-connect inspect
```

Other private transfer channels work too; the worker itself does not require SSH.
Use a unique name and invitation for each node. Invitations expire after one hour.
If installation stops after saving state, fix the cause and run
`sudo deepai-connect resume`. Preserve `/var/lib/deepai-connect` and device identities.

## Manage the cluster

From your laptop, using SSH key/agent authentication:

```sh
deepai-connect setup --hub root@187.7.75.65
deepai-connect doctor
deepai-connect nodes --json
deepai-connect vm resources   # when setup includes --vm NAME
deepai-connect containers
```

In PowerShell, use `.\deepai-connect.exe` if the command is not on PATH.
See the [operating guide](docs/unified-connect.md) for logs, publishing and recovery.
Agents can load the focused [Connect lifecycle skill](.agents/skills/deepai-connect-lifecycle/SKILL.md)
for installation, start/stop, startup preferences and diagnosis.
Use supported CLI commands and their structured output for agent operation;
the skill records prerequisites, permissions and recovery steps. Installing the
binary alone does not install or enable the repository skill.

`nodes` shows one row per node with CPU, memory and disk capacity and usage
percentages. Add `--details` for scheduling budgets, storage and diagnostics, or
`--json` for structured output. For Mac workers, the Linux VM determines what
the cluster can use. `vm create` and `vm configure`
accept explicit CPU, memory and disk grants and preview changes before `--apply`. See
[worker resource grants](docs/unified-connect.md#worker-resource-grants).

## Do I need the Tailscale client?

Only for direct access to private IPs from your laptop: follow
[client enrollment](docs/unified-connect.md#native-clients-and-workload-routing).
SSH administration needs no Tailscale app; Linux hubs/workers embed the mesh engine.
Published HTTPS applications need only a browser. A client does not contribute compute.
The coordinator URL is the native client's control server, not the human platform
sign-in URL.

## Availability and recovery boundaries

A single VPS is a failure domain for coordination, the Kubernetes control plane
and public ingress. Cached mesh state can restore trusted peer connectivity
without a running coordinator or Kubernetes, but cannot replace etcd quorum and
expires after 30 days without authenticated synchronization. Preserve device
identities and the original state directory; use `resume` for interrupted setup.

Multiple hubs and three or five voters are supported topology options;
independent-host failover and cross-region control planes still need
qualification. Worker shutdown removes its compute and interrupts local
workloads. Node disks are not a shared storage pool, and retained local volumes
are not off-host backups. Application storage needs its own redundancy and
[consistent backups](docs/unified-connect.md#durable-state-and-recovery).

## Development

With Go 1.26.9+, run `go run ./cmd/release -version VERSION` to build all six binaries.
Tagged CI builds publish binaries and checksums; build the service image separately.
CI includes native CLI checks; Windows amd64 executes on a Windows runner and
Windows arm64 is cross-compiled. Build success is distinct from runtime
qualification. This README describes the source contract, not live cluster health.

[Architecture](docs/architecture.md) · [Tests](docs/testing-unified.md) · [MIT license](LICENSE)
