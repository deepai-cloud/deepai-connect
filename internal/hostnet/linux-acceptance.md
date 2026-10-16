# Host transport acceptance in isolated Linux namespaces

`TestLinuxNamespaceAcceptance` exercises the production host agent, real Linux
TUN devices, kernel routes, and iptables. Ordinary `go test` skips it unless the
explicit environment opt-in is present. It can run on an existing VPS without
installing Connect or K3s there.

The caller needs root, `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `/dev/net/tun`, `iproute2`
with JSON output and namespace support, `iptables`, `iptables-save`, `sysctl`,
and `curl`. A container without these capabilities is insufficient. No public
DNS, Internet connectivity, Docker, Kubernetes, certificates, or Go installation
is required on the target when using a precompiled test binary.

## Build and run

From the `deepai-connect` module directory, build for the VPS architecture:

```sh
acceptance_build_dir=$(mktemp -d)
GOTOOLCHAIN=auto CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go test -c -o "$acceptance_build_dir/hostnet-acceptance-amd64.test" ./internal/hostnet
# Use GOARCH=arm64 for an aarch64 VPS.
printf '%s\n' "$acceptance_build_dir/hostnet-acceptance-amd64.test"
```

Copy the binary at the printed path to the selected VPS, then remove the temporary
build directory. Keep test binaries separate from the release-only `dist/`.
On that VPS, run the exact test
with root privileges; capture its exit status as well as its output:

```sh
set -o pipefail
sudo env DEEPAI_CONNECT_PRIVILEGED_TEST=isolated-netns \
  ./hostnet-acceptance-amd64.test \
  -test.run='^TestLinuxNamespaceAcceptance$' -test.v -test.timeout=5m \
  2>&1 | tee hostnet-acceptance.log
```

The test has its own four-minute deadline. Do not reduce the outer timeout below
five minutes: it must leave time for cleanup after a failed assertion. SIGINT
and SIGTERM trigger cancellation and cleanup; SIGKILL and a host crash cannot.

## What a pass establishes

The harness creates four uniquely named namespaces: two hosts, one pod, and an
isolated underlay bridge with a TLS DERP server. Every network mutation executes
inside one of these namespaces. Its veth pairs are created directly inside the
test namespaces; the caller never receives a test bridge or interface.

It verifies:

- Real HTTP traffic over encrypted WireGuard between the two host addresses.
- Pod-to-private-host traffic retaining the pod source address, the encrypted
  reply path, and private-host-to-pod traffic through a CNI-style bridge.
- Existing exact CNI routes, an unrelated route and firewall chain, and the
  physical default route remain intact throughout agent startup and recovery.
- Both agents restart from their saved identities and trusted peer snapshots
  while no coordinator, Kubernetes API, cluster DNS, or DERP exists.
- A real kernel FORWARD deny in a kube-router-style chain blocks the selected
  private-host-to-pod flow before and after agent restart, while control and
  allowed pod traffic continue; removing the policy restores the same flow.
- With direct WireGuard UDP dropped by iptables, live NetInfo discovers the
  isolated TLS DERP and the same traffic succeeds through it. Positive UDP DROP
  counters and DERP bytes received/sent substantiate this fallback.
- The caller's routes, policy rules, and firewall snapshot are unchanged after
  test processes and namespaces have been removed. Concurrent administrative
  changes can fail this final comparison and should be investigated.

No coordinator is started. The harness exchanges the two discovered HomeDERP
values through the existing local state API; coordinator protocol behavior has
separate tests. The relay's certificate is pinned only in these test snapshots.

This test uses a simulated CNI topology and policy chain. It does not establish
K3s recovery, actual kube-router policy reconciliation, etcd quorum or
cross-region reliability, NAT interoperability, Internet egress, relay failover,
or public ingress. Use [the cluster acceptance procedure](../../docs/testing-unified.md)
for the complete deployment checks.

## Cleanup and failure evidence

The same compiled test binary also provides a focused routing/NAT lifecycle
check that needs only `ip`, `iptables`, `iptables-save`, and `sysctl`:

```sh
sudo env DEEPAI_CONNECT_PRIVILEGED_TEST=isolated-netns \
  ./hostnet-acceptance-amd64.test \
  -test.run='^TestLinuxEgressPolicyLifecycle$' -test.v -test.timeout=90s
```

It uses one fresh namespace and dummy interfaces to exercise production egress
operations with actual iproute2 JSON. Both pod-prefix and host-/32 policies must
select the overlay, retain an unreachable fallback during shutdown, recover on
restart, and remove only their owned state on repeated explicit disable. It
also simulates CNI replacement/removal of tracked routes during gateway
withdrawal and reselection. This test checks kernel routing and cleanup;
actual Internet transport and gateway failover still require cluster checks.

The local VXLAN listener boundary has a separate three-namespace check:

```sh
sudo env DEEPAI_CONNECT_PRIVILEGED_TEST=isolated-netns \
  ./hostnet-acceptance-amd64.test \
  -test.run='^TestLinuxVXLANBoundary$' -test.v -test.timeout=60s
```

It sends real UDP8472 packets to the listener's underlay and overlay addresses,
including a forged overlay source, broadcast, and multicast. These must be
blocked outside the overlay interface, even after another component prepends
an unconditional filter INPUT ACCEPT. Overlay ingress and unrelated forwarded
UDP8472 must still arrive. It also verifies repeated installation, duplicate
cleanup, preservation of unrelated rules, and unchanged caller networking.
The live cluster procedure additionally tests actual VXLAN decapsulation.

Large TCP transfers through nested VXLAN have a focused regression:

```sh
sudo env DEEPAI_CONNECT_PRIVILEGED_TEST=isolated-netns \
  ./hostnet-acceptance-amd64.test \
  -test.run='^TestLinuxVXLANBulkTransfer$' -test.v -test.timeout=4m
```

It binds real VXLAN devices to the Connect TUNs and verifies fourteen
SHA256-checked 256KiB uploads/downloads in both directions. Two ingress policy
deny/remove cycles require positive counters on the intended DROP rule and
complete transfers immediately after removal, without retries. VXLAN interface
counters establish that the payload used the nested tunnel.

On a busy K3s host, unrelated CNI reconciliation can change the caller's firewall
during the strict final snapshot comparison. Run this test inside an additional
disposable caller namespace to keep that comparison isolated:

```sh
sudo unshare --net env DEEPAI_CONNECT_PRIVILEGED_TEST=isolated-netns \
  ./hostnet-acceptance-amd64.test \
  -test.run='^TestLinuxVXLANBulkTransfer$' -test.v -test.timeout=4m
```

`unshare` requires util-linux and the same namespace privileges. The outer
namespace has no external interfaces and disappears when the test exits; the
harness cleans its four inner namespaces. Existing agents and workloads keep
running. Snapshot comparisons ignore IPv6 route expiry countdowns and live
firewall counters, while retaining routes, rules, ownership and rule ordering.

Stale relay connections after an unobservable parent NAT/VPN change have a
separate regression, also suitable for the disposable caller namespace:

```sh
sudo unshare --net env DEEPAI_CONNECT_PRIVILEGED_TEST=isolated-netns \
  ./hostnet-acceptance-amd64.test \
  -test.run='^TestLinuxStaleNATPathRecovery$' -test.v -test.timeout=4m
```

This test also needs `ss` from iproute2. It uses the real Noise coordinator and
TLS relay. A timed-out control request followed by a fresh authenticated map
must preserve a healthy relay's existing TCP connection. It then drops UDP and
the old relay TCP tuple while allowing new connections, without changing the
guest interface or default route. After control connectivity is restored, a
complete SHA256-checked 256KiB transfer must finish within fifteen seconds
through a new relay connection, while the old tuple remains blocked. The
measured recovery starts at control restoration, not at a VPN switch. The
fixture uses a three-second control request timeout to shorten the test;
production retains its fifteen-second timeout. No payload retry hides a stall.
This does not test silent relay loss while every control request succeeds;
without a detected path change, that case retains upstream relay timeout behavior.

Successful and ordinary failing runs remove their private temporary state,
processes, and exact generated namespace names. Failure output includes the
isolated agent logs; it does not print private identity files. The harness never
flushes or rewrites the caller's firewall, routes, or forwarding settings.

If the process was killed with SIGKILL or the machine interrupted cleanup, use
the exact namespace names printed at startup. Inspect `ip netns list`, stop only
the processes listed by `ip netns pids EXACT_TEST_NAMESPACE`, and delete that
specific namespace with `ip netns delete EXACT_TEST_NAMESPACE`. Do not delete
other namespaces or run host firewall cleanup commands. A normal rerun uses new
names and never adopts another run's namespaces.
