# Architecture

DeepAI Connect runs one K3s cluster over one persistent host overlay. The Linux
amd64/arm64 executable exposes cluster creation, enrollment, recovery, routing
and publication commands. It also runs the host agent and cluster-managed
coordinator and relay processes.
Installations are greenfield; migration from the earlier separate Connect or
Compute deployments is outside the supported workflow.

## Host networking and Kubernetes

`deepai-connect-agent.service` owns the host's `deepai0` interface through the
upstream Tailscale WireGuard engine. It persists machine, node and discovery
identity, approved policy, peer endpoints and relay information. At startup it
restores that state before accepting new coordination updates.

`deepai-connect-k3s.service` requires the agent and waits for its readiness gate.
K3s advertises overlay addresses and binds Flannel to `deepai0`. Kubernetes uses
distinct host, pod and Service ranges. The first hub initializes embedded etcd;
additional hubs join as voting or non-voting control-plane servers. Workers
run K3s agents. Voter admission is serialized and checks cluster health.

Existing CNI and host firewall rules retain their ownership. Connect's routing
and firewall code manages its own rules, preserves forwarding denials, and
keeps the physical default route. Internet egress requires an explicit gateway
role and per-source opt-in.

## Shared control services

The coordinator implements Tailscale registration and network-map protocols.
Replicas share membership, address allocation, policy and enrollment state in a
namespaced `NetworkState` custom resource. Kubernetes `resourceVersion` provides
compare-and-swap updates. Secrets `connect-coordinator-keys`,
`connect-enrollment` and `connect-gateway-tls` hold the shared Noise identity,
enrollment/admin/relay credentials and gateway TLS identity respectively.
Device private keys remain on their hosts. A Kubernetes Lease serializes shared
service reconciliation across hubs.

Each hub runs DERP/STUN and a Caddy HTTPS gateway. Direct encrypted peer paths
are preferred; DERP forwards encrypted packets when direct connectivity fails.
Public application requests follow Caddy → Traefik → Kubernetes Service.
Publishing creates an Ingress and updates the configured gateway hostnames.

CoreDNS and Traefik each run at least two replicas on protected hub nodes, with
preferred spreading across hostnames. The first hub can host both replicas;
additional hubs allow separate placement. Create, join, and resume reconcile
these dependencies and wait for readiness. The coordinator also checks them
every 30 seconds so packaged K3s or Helm reconciliation after reboot cannot
leave them at a single replica. Narrow patches preserve their packaged images,
configuration, service accounts, and Services.

Secret-bearing services use the administrator-applied
`connect.deepai.cloud.node-restriction.kubernetes.io/role=hub` label.
NodeRestriction prevents worker kubelets from assigning it to attract those pods.
Worker enrollment receives expiring bootstrap credentials; hub enrollment
requires a separate role-authorized invitation and receives server credentials.

## Code boundaries

| Path | Responsibility |
| --- | --- |
| `cmd/deepai-connect` | Primary command entry point into `internal/unified` |
| `internal/unified` | Host lifecycle, operator commands and component integration |
| `internal/hostnet` | Overlay identity, transport, routes, firewall and cached recovery |
| `internal/coordinator` | Tailscale protocol, durable registry and Kubernetes state store |
| `internal/enrollment` | Signed, resumable role-specific admission and credential release |
| `internal/cluster` | K3s configuration, systemd ordering and Kubernetes services |
| `internal/relay` | Owned DERP/STUN process and peer admission |
| `internal/platform` | Private files, directory and process locks |
| `cmd/release`, `internal/buildinfo` | Linux artifacts, checksums and embedded version |
| `internal/architecture` | Standalone module and supported executable-target checks |

Architecture tests verify the standalone module has no replacements, includes
the executable on Linux amd64/arm64, and excludes it on unsupported targets.
Release builds ignore parent Go workspaces and reset architecture optimization
flags to the supported baseline CPUs.

## Persistence and recovery

Host state defaults to `/var/lib/deepai-connect`. `unified.json` records the
installation phase, `network/` contains the overlay identity and trusted cache,
and `cluster/` contains K3s configuration and datastore files. Writes precede
runtime transitions so interrupted operations can resume with the same device
and cluster identity. Worker credential reloads are journaled; a confirmed join
does not become pending again during a later API outage.

Networking can restore cached peer connectivity while Kubernetes and its
coordinator are unavailable. Cached trust has a bounded lifetime. Back up host
state, K3s server tokens, etcd snapshots and application volumes using their
respective consistency requirements. See the [operating guide](unified-connect.md)
and [Linux acceptance procedure](testing-unified.md) for exact commands and
failure assertions.

The host agent reports successful authenticated map application to the upstream
transport's control-health tracker. This permits a new home relay to be
selected and advertised while coordination is available. Offline cache startup,
failed or invalid map requests, cancellation, and shutdown clear that signal;
cached connectivity alone cannot authorize a relay-location change.

After a coordinator transport timeout, the next authenticated, persisted map
triggers upstream path rebinding and discovery. Key discovery uses a fresh
connection pool so a stale HTTPS connection cannot block that recovery.
A relay-only failure with healthy control requests does not trigger rebinding
and can still wait for upstream's receive timeout (about 120 seconds). No fixed
recovery bound or survival of in-flight requests is promised for NAT/VPN changes.

## Distribution

`go run ./cmd/release -version BUILD` produces Linux arm64/amd64 executables,
`manifest.json` and `SHA256SUMS`. The release builder stages the complete output
and preserves the previous output on compilation failure. The Dockerfile builds
the same executable for the coordinator and relay image. Host K3s is a separate
pinned, verified dependency.

The release builder does not upload or sign artifacts. Distribute executables,
images and checksums; keep installation state and credentials private.
