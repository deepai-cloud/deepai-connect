# This Mac as compute — 30 October 2026

The current Mac now runs a separate Linux compute worker, `mac-worker-2026`,
registered as `connect-9` at `100.96.0.9`. Native Mac private access remains
`connect-8` at `100.96.0.8`; the old remote worker remains `connect-4`.
The [worker setup skill](../.agents/skills/deepai-connect-worker-setup/SKILL.md)
and [native access skill](../.agents/skills/deepai-connect-native-access/SKILL.md)
keep these roles distinct.

## Installation and startup

- Canonical Multipass 1.16.4+mac, QEMU, Ubuntu 24.04 arm64 guest; 2 vCPUs,
  4 GiB RAM and a 20 GiB sparse disk. No host directory mounts.
- Connect `gateway-api-20261018.2`, built from the exact compatible deployed
  baseline, and checksum-verified K3s `v1.36.4+k3s1`. Adding this worker did not
  require deploying repository main or replacing hub services.
- One bounded worker invitation was transferred privately, consumed once and
  its temporary hub/guest copies removed. Existing identities were retained.
- Guest `deepai-connect-agent.service` and `deepai-connect-k3s.service` are
  enabled and active; K3s requires and starts after the mesh agent.
- The desktop user's `cloud.deepai.connect.vm.mac-worker-2026.plist` is configured
  and enabled through `vm startup enable`. It starts the selected VM at user
  login. Multipass's system daemon and Linux guest boot are separate mechanisms.

## Dated acceptance

At 20:29–20:32 UTC the node was Ready and schedulable, with 2 CPUs and
3,995,108 KiB allocatable memory. A bounded non-root BusyBox HTTP pod ran on this
node with 10m CPU/16 MiB requests, 100m/32 MiB limits and a ten-minute deadline.
The hub received the exact expected response from the worker's pod IP.
The owned test namespace and pod were removed after proof; absence was verified.

The worker's encrypted probe to the hub used a direct path; traffic to the native
Mac also passed over DERP. A relayed response proves connectivity without proving
a direct peer path. Existing node identities and hub service images were preserved.

Chrome light/dark checks showed five Devices and three Compute entries, with
the new worker ON and the native Mac excluded from Compute. Reciprocal links
selected `connect-9` correctly. Node-exporter became Ready and CPU/memory/disk
metrics appeared by 20:31:23 UTC. The original System theme was restored.

Sanitized evidence lives in the parent workspace's
`local-setup/mac-compute-2026-10-30/`: `status.json` is the completion entrypoint;
`binaries.json`, `guest-startup.txt`, `mac-login-startup-final.json`,
`workload-proof.json`, `browser-acceptance.json` and `browser-metrics-final.json`
record individual checks. Installer provenance and README publication have
separate receipts there. Do not copy private identity/configuration files.

## Operation and limits

Use `deepai-connect vm status --name mac-worker-2026 --json`, `vm resources`,
`vm startup status --name mac-worker-2026 --json`, `nodes --json` and `network
--json` for inspection. Preserve the same VM and guest state directory; diagnose
and resume existing state instead of issuing another invitation.

Configured automatic startup and currently running daemons do not establish a
successful real reboot/login. No reboot, logout, sleep or disruptive stop/start
was performed. Windows workers remain unqualified. This enrollment does not
migrate the old Mac's native inference runtime or its credentials. Current health
must be read live; these observations are not a future availability guarantee.
