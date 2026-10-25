# Unified Connect acceptance tests

Run the ordinary suite first, then the applicable live tests below. Record the
commit, binary/image hashes, architecture, kernel, topology, UTC times and
`PASS`, `FAIL` or `NOT RUN` for each scenario. Preserve private evidence; never
include credentials or raw Secret/NetworkState exports in a public report.

## Automated checks

From this module with its required Go toolchain:

```sh
GOWORK=off go vet ./...
GOWORK=off go test -race ./...
GOWORK=off go test -race -tags=integration,vpsintegration ./internal/coordinator -count=1
GOWORK=off go run ./cmd/release -version acceptance-001 -out dist
(cd dist && sha256sum --check SHA256SUMS)
```

The [isolated Linux harness](../internal/hostnet/linux-acceptance.md) provides
opt-in real-kernel checks for encrypted host/pod forwarding, cached restart,
firewall coexistence, DERP fallback, egress cleanup and the VXLAN receive
boundary. It creates its own namespaces and compares the caller's kernel state
after cleanup. Follow that document's exact build, opt-in and timeout commands;
keep unrelated network administration paused during its comparison.

## Performance regression checks

The [2026-10-25 source simplification report](source-simplification-2026-10-25.md)
records the behavior-preserving NAT/CLI refactor, measured production reduction,
baseline-equivalence checks and the live-validation boundary.

Run microbenchmarks without race instrumentation, using the same Go version and
machine for comparisons:

```sh
GOWORK=off go test ./internal/hostnet -run '^$' -bench 'Benchmark(StateClone|PeerForIP|TransportState)$' -benchmem -count=5
GOWORK=off go test ./internal/coordinator -run '^$' -bench '^BenchmarkMapForState$' -benchmem -count=5
GOWORK=off go test ./internal/cluster -run '^$' -bench '^BenchmarkInfrastructurePatch$' -benchmem -count=5
GOWORK=off go test ./cmd/release -run '^$' -bench '^BenchmarkChecksumFile$' -benchmem -count=5
```

State copies use deep-copy helpers instead of JSON round trips. Peer routing
indexes are built when a map is applied and published atomically with that
snapshot; longest-prefix matching and equal-prefix ordering remain covered by
tests. Kubernetes clients drain bounded response leftovers, allowing repeated
requests to reuse authenticated connections. Connection tests verify one TLS
connection for five successive calls, including conflict responses. Control
key discovery still uses fresh connections for recovery after uplink changes.

## Live deployment preparation

Use three disposable Linux VMs for quorum testing and a fourth worker behind a
separate NAT. An additional non-voter hub is optional. A Mac-hosted Linux arm64
VM plus a remote amd64 hub establishes a real cross-host worker path, but does
not establish a three-voter quorum. Never substitute several processes sharing
one VPS kernel for independent-host or cross-region evidence.

Install the pinned K3s binary and same-version Connect binaries/image using the
[operating guide](unified-connect.md#requirements). Use non-overlapping host,
pod, Service and underlay ranges; reachable hub UDP endpoints; distinct relay
DNS names; and a trusted certificate covering coordination, relays and the test
application. Record the multi-platform image digest. Workers must pull an image
for their actual architecture. Do not bypass TLS verification.

Create hub-1 with `--voters 3`, then issue individual voter invitations and join
hub-2 and hub-3 **sequentially**, following the guide. Join worker-1 with a worker
invitation. To test a non-voter, issue a hub invitation without `--voter`: the
new hub must serve the API, relay and gateway without adding an etcd member.

Only run the destructive fault sections on disposable VMs with console access
and a pre-installation snapshot. In each root Bash shell used for those faults:

```sh
export DEEPAI_CONNECT_ACCEPTANCE=disposable-vm
guard() {
  test "${DEEPAI_CONNECT_ACCEPTANCE:-}" = disposable-vm &&
  test "$(id -u)" = 0 && systemd-detect-virt --vm --quiet
}
guard || exit 1
umask 077
mkdir -p /root/connect-acceptance
```

On each installed hub, use its administrator kubeconfig and overlay-bound API
address. The helper requires `jq`:

```sh
k() {
  k3s kubectl --kubeconfig /var/lib/deepai-connect/cluster/kubeconfig \
    --server="https://$(jq -r .overlayIP /var/lib/deepai-connect/cluster/cluster.json):6443" \
    --request-timeout=15s "$@"
}
k get --raw=/readyz
k get nodes -o wide
k -n deepai-system get deployments,daemonsets,pods
k -n kube-system get deployment coredns traefik
```

Require the assigned overlay address on every Node, unique PodCIDRs, exactly
three voting etcd members, two ready CoreDNS/Traefik replicas and the expected
hub service counts. Inspect the protected hub selector and placement. Use the
pinned release's `etcdctl` with the local etcd CA/client certificate to record
member IDs and run `endpoint health --cluster`; Node Ready alone is insufficient
proof of a functioning quorum. Preserve those IDs for later comparisons.

On every node, save identity hashes and the physical default route:

```sh
sha256sum /var/lib/deepai-connect/network/identity.json \
  /var/lib/deepai-connect/enrollment.key \
  > /root/connect-acceptance/identity.sha256
ip -j route show default > /root/connect-acceptance/default.json
```

## Workload and path assertions

Create one small HTTP pod on each node; its fixed 128 KiB response also detects
MTU/fragmentation failures that short readiness requests can miss:

```sh
k apply -f - <<'YAML'
apiVersion: v1
kind: Namespace
metadata: {name: connect-acceptance}
---
apiVersion: apps/v1
kind: DaemonSet
metadata: {name: web, namespace: connect-acceptance}
spec:
  selector:
    matchLabels: {app: acceptance-web}
  template:
    metadata:
      labels: {app: acceptance-web}
    spec:
      containers:
        - name: web
          image: caddy:2.11.6-alpine
          command: [sh, -ec]
          args:
            - mkdir -p /tmp/www;
              dd if=/dev/zero of=/tmp/www/payload bs=1024 count=128;
              exec caddy file-server --listen :8080 --root /tmp/www
          readinessProbe:
            httpGet: {path: /payload, port: 8080}
---
apiVersion: v1
kind: Service
metadata: {name: web, namespace: connect-acceptance}
spec:
  selector: {app: acceptance-web}
  ports: [{port: 8080, targetPort: 8080}]
YAML
k -n connect-acceptance rollout status daemonset/web --timeout=180s
k -n connect-acceptance get pods -o wide
deepai-connect publish --hostname app.example.com \
  --service connect-acceptance/web --port 8080
```

Use the hostname covered by your certificate. On every node, fetch every pod's
`http://POD_IP:8080/payload` and the Service's ClusterIP URL, save the response,
and compare its SHA-256 with 128 KiB of zero bytes. Obtain addresses from
`k -n connect-acceptance get pods,service -o wide`. Repeat from a pod on another
node using `k exec POD -- wget -qO- URL`. Prove both directions across the actual
WAN, including the remote hub to the Mac worker's pod and that pod to the hub.

Inside the worker pod, resolve `kubernetes.default.svc.cluster.local` and reach
the test Service by `web.connect-acceptance.svc.cluster.local:8080`. Inspect
`deepai0`, `flannel.1` and pod-interface MTUs; verify large payload hashes on both
direct and relayed paths. A Ready worker or a successful host-only ping does not
prove CNI, DNS, image architecture or Service routing.

From outside the overlay, request `/readyz` and the application's `/payload`
through each public hub using `curl --resolve HOST:443:HUB_IP`. Record TLS and
payload results per hub. An HTTP result through one DNS answer does not prove
all gateways work. On each node, compare the saved physical default and inspect
CNI routes, `KUBE-SERVICES` and existing firewall rules after every restart.
The isolated kernel harness covers exact unrelated-route/firewall sentinels.

## Worker security and real NAT

On the actual Linux worker, its kubelet credentials must be refused when they
try to grant protected hub placement. A server-side dry run leaves state intact
even if the assertion unexpectedly fails:

```sh
if k3s kubectl \
  --kubeconfig /var/lib/deepai-connect/cluster/k3s/agent/kubelet.kubeconfig \
  label node worker-1 \
  connect.deepai.cloud.node-restriction.kubernetes.io/role=hub \
  --overwrite --dry-run=server \
  > /root/connect-acceptance/label-denial.txt 2>&1; then
  echo 'FAIL: worker can grant hub placement' >&2; exit 1
fi
grep -q Forbidden /root/connect-acceptance/label-denial.txt
```

Verify the worker runs the K3s agent, has no etcd/control-plane role, and received
an expiring bootstrap credential rather than the server token, without printing
either. Its original keys and address must survive `resume` and a VM reboot.
Interrupt an initial join, then resume with the same state; do not recreate it.
Expired unfinished-worker token recovery and revocation are also covered by the
enrollment/worker-resume regression tests.

For the Mac VM, record its private address, NAT/uplink and discovered peer
endpoints. Test normal direct discovery first. Then force DERP on **that worker
only**, preserving direct paths among hubs. In the disposable worker shell:

```sh
guard || exit 1
clear_udp_fault() {
  for xt in iptables ip6tables; do
    for chain in INPUT OUTPUT; do
      "$xt" -D "$chain" -p udp --dport 41641 \
        -m comment --comment connect-acceptance-derp -j DROP 2>/dev/null || true
    done
  done
}
trap clear_udp_fault EXIT INT TERM
for xt in iptables ip6tables; do
  for chain in INPUT OUTPUT; do
    "$xt" -I "$chain" 1 -p udp --dport 41641 \
      -m comment --comment connect-acceptance-derp -j DROP
  done
done
```

Repeat exact host/pod/Service payload and DNS assertions. Require increasing UDP
DROP counters and transport `via=derp`/relay-region evidence. To test another
relay, identify the receiver's current `HomeDERP` and corresponding hub from its
saved public overlay map. On **that disposable hub only**, keep the relay down
for the test, including STUN; deleting a DaemonSet pod is insufficient because
it is immediately recreated:

```sh
guard || exit 1
clear_relay_fault() {
  iptables -D OUTPUT -o lo -p tcp --dport 3340 \
    -m comment --comment connect-acceptance-relay -j REJECT \
    --reject-with tcp-reset 2>/dev/null || true
  for xt in iptables ip6tables; do
    "$xt" -D INPUT -p udp --dport 3478 \
      -m comment --comment connect-acceptance-relay -j DROP 2>/dev/null || true
  done
}
trap clear_relay_fault EXIT INT TERM
iptables -I OUTPUT 1 -o lo -p tcp --dport 3340 \
  -m comment --comment connect-acceptance-relay -j REJECT --reject-with tcp-reset
for xt in iptables ip6tables; do
  "$xt" -I INPUT 1 -p udp --dport 3478 \
    -m comment --comment connect-acceptance-relay -j DROP
done
```

With coordinator `/readyz` healthy and direct worker UDP still blocked, require
a different advertised home relay and identical payload recovery within the
chosen deadline (for example 180 seconds). Record actual interruption and fresh
TCP attempts. Call both cleanup functions in their original shells even after
failure, then verify direct traffic recovers. A firewall simulation supplements
real NAT discovery; it does not establish arbitrary symmetric-NAT compatibility.

## Policy, egress and infrastructure checks

| Scenario | Required assertion and cleanup |
| --- | --- |
| Kubernetes NetworkPolicy | On the test namespace, apply a deny policy selecting `app: acceptance-web`. A fresh request to a **remote** pod must fail while its host's overlay endpoint remains reachable. Restart that host's agent before restarting K3s; denial must persist. Inspect the policy counter/hook ordering, delete the exact policy, and require the same payload to recover. Own-node traffic and unavailable workloads are not valid denial evidence. |
| CoreDNS/Traefik repair | Save packaged settings, scale each deployment to one replica, and wait for background repair to two ready replicas without a lifecycle command. Require protected hub placement/spreading and unchanged images, configuration, volumes and service accounts; repeat after reboot. |
| Internet opt-in | Enable `gateway --interface UPLINK` on a hub and `egress --source ACTUAL_WORKER_PODCIDR` on the worker. Pod Internet requests must increment worker and gateway NAT counters. Private traffic must retain its original pod source. Main defaults and Kubernetes/overlay paths remain intact. |
| Gateway failure | With two approved gateways, stop the selected gateway or revoke its default route. Fresh Internet requests must switch to the other gateway; record convergence. Keep the public coordinator origin available independently. |
| Consumer stop and disable | Stop the agent while a pod remains alive: opted-in Internet fails, source rules plus table-186 unreachable fallback remain, ordinary host uplink works. Resume restores it. `egress --disable` removes owned source/routing state; `gateway --disable` removes scoped NAT/approval. Verify durable cleanup intents clear and unrelated rules remain. |
| Expired cache | On a disposable snapshot with original keys backed up, expire only cache timestamps. Startup refuses it; authenticated `refresh` and `resume` recover the same identity. Rejection, unavailable control or bad TLS must leave cache/keys unchanged. See the operating guide and refresh regressions. |

## Quorum and simultaneous cached restart

First save the three member IDs, identity hashes and a durable marker:

```sh
k -n connect-acceptance create configmap recovery-marker --from-literal=value=preserve
k -n connect-acceptance get configmap recovery-marker -o json \
  > /root/connect-acceptance/marker-before.json
```

Power off one voter through its VM console: the two remaining voters must commit
etcd health proposals and a new API write. Restore it and require all original
members healthy. Power off two voters: the remaining one must fail a new
committed proposal/write. Restore both and require the original IDs, marker
UID/data and new writes. A client timeout does not prove a write was never
committed. Do not use cluster reset, re-enrollment or a new datastore to pass.

For the cold-start test, stop coordinator and relay workloads first:

```sh
guard || exit 1
k -n deepai-system scale deployment/connect-coordinator --replicas=0
k -n deepai-system patch daemonset/connect-relay --type=merge -p \
  '{"spec":{"template":{"spec":{"nodeSelector":{"connect.deepai.cloud/acceptance-disabled":"true"}}}}}'
```

Confirm all coordinator and relay pods have stopped. Through VM consoles,
power off **all** hubs before starting any. Restart the same disks together.
Within a recorded deadline, require agent readiness before K3s, original
identity hashes, all three healthy etcd members, Ready nodes, unchanged marker
UID/data and a new write while coordinator/relay counts remain zero. Check
cross-node payloads and firewall/CNI state. Cached recovery relies on reachable
direct hub endpoints; blocking every such path and the shared relay is a
combined control/transport partition, not this recovery test.

Restore the services only after recording those assertions:

```sh
guard || exit 1
k -n deepai-system patch daemonset/connect-relay --type=json -p \
  '[{"op":"remove","path":"/spec/template/spec/nodeSelector/connect.deepai.cloud~1acceptance-disabled"}]'
k -n deepai-system scale deployment/connect-coordinator --replicas=2
deepai-connect resume
sha256sum --check /root/connect-acceptance/identity.sha256
```

Repeat on the intended independent hosts/regions and record RTT, loss, write
latency and recovery thresholds before claiming that topology. Five-voter
operation needs five actual voters. K3s's
[multicloud guidance](https://docs.k3s.io/networking/distributed-multicloud)
excludes distributed embedded etcd from its documented multicloud support.

## External native-client harness

The opt-in `vpsintegration` test uses an unmodified upstream `tsnet` client on
the workstation, without changing host routes or using SSH. Enroll a separate
native-client key, retain its private state directory, and set real URLs and
expected SHA-256 hashes for controlled responses:

```sh
export DEEPAI_VPS_CONTROL_URL=https://mesh.example.com
export DEEPAI_VPS_AUTH_KEY_FILE=/absolute/private/client.key
export DEEPAI_VPS_STATE_DIR=/absolute/private/native-state
export DEEPAI_VPS_POD_URL=http://ACTUAL_POD_IP:8080/payload
export DEEPAI_VPS_SERVICE_URL=http://ACTUAL_SERVICE_IP:8080/payload
export DEEPAI_VPS_HUB_URL=http://ACTUAL_HUB_OVERLAY_IP:18080/payload
export DEEPAI_VPS_POD_SHA256=EXPECTED_SHA256
export DEEPAI_VPS_SERVICE_SHA256=EXPECTED_SHA256
export DEEPAI_VPS_HUB_SHA256=EXPECTED_SHA256
go test -tags=vpsintegration -run '^TestVPSNativeInteroperability$' \
  -count=1 -v -timeout=15m ./internal/coordinator
```

Provide the controlled hub listener separately. `DEEPAI_VPS_EXPECT_PATH=direct`
or `derp` requires native discovery evidence. For a fault round, set a fresh
`DEEPAI_VPS_BARRIER_FILE`, wait for its `.ready` baseline marker, apply the fault
from the VM console, then create the barrier file. `DEEPAI_VPS_AFTER_PATH` and
`DEEPAI_VPS_DURATION=30s` check convergence/repeated traffic. Set
`DEEPAI_VPS_NATIVE_ENDPOINT_FILE` and `DEEPAI_VPS_EXPECT_BODY` to test a pod's
reverse request to the same native client while it waits.

Policy runs can set `DEEPAI_VPS_EXPECT_DENIED_AFTER_BARRIER=POD` while retaining
a positive hub control. `DEEPAI_VPS_ALLOW_POLICY_REJECT=1` accepts pinned
kube-router's specific target-matching connection-refused response only when
its REJECT counter increases and policy removal restores the original endpoint.
See [the harness](../internal/coordinator/vps_integration_test.go) for the full
parameters. An unavailable workload or generic connection error is not proof of
policy enforcement.

Policy deletion is asynchronous. Before asserting restored traffic, observe
the selected pod's firewall chain and wait for the deleted policy's references
to disappear. An API acknowledgement or fixed sleep does not establish that
kube-router has reconciled the change. Then make a single payload request;
do not retry failed transfers into a passing result.

## Cleanup

Remove exact fault rules, restore service counts and disable optional egress
before cleanup. Delete only `connect-acceptance` and its resources. Destroy the
disposable VMs/disks or restore their pre-installation snapshots; remove test
DNS, invitations and certificates according to the retention policy. Preserve
private logs/disks if recovery fails. Never flush host routing/firewall tables,
restore a stale iptables dump over running CNI, or replace identities to hide a
failure. Production backup/restore follows the operating guide and the pinned
K3s procedure, including retention of the server token with etcd snapshots.
