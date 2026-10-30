# Bounded coordinator presence — 2026-10-30

An open HTTP/2 map stream previously refreshed a device's `LastSeen` on the
server heartbeat without a bounded check for incoming frames. `IdleTimeout`
alone does not close an active stream. A half-open connection could therefore
keep a disconnected client apparently current.

The control server now uses a 25-second read-idle interval, a 15-second PING
acknowledgement timeout and a 15-second stalled-write timeout. Heartbeats check
cancellation and flush successfully before updating `LastSeen`. Both KeepAlive
and full-map heartbeat clients follow that rule. Healthy idle clients remain
connected by acknowledging HTTP/2 PING. No device identity is removed when its
connection closes, and reconnect uses the existing registration.

This bounds control presence, not mesh application traffic or physical power.
With App Foundation's 90-second presence window, a lost control connection may
take up to 130 seconds plus collection delay to appear Offline. A working
control connection does not establish a working peer data path.

## Verification

Synthetic authenticated HTTP/2 peers exercise healthy idle, missing PING ACK,
failed heartbeat flush, stalled writes, preserved identity and reconnect for
both heartbeat variants. Frozen-release coordinator race tests and vet passed,
as did upstream native-client automatic and forced-DERP integration. The current
repository coordinator race tests and vet also passed.

Live App inventory initially showed `connect-4` (old VM) and `connect-7` (old
native Mac) Offline while retaining them alongside the hub and new native Mac.
The VM reconnected first, with compute Unknown until its Kubernetes heartbeat
recovered. By 20:04:04Z all four registrations were Connected, hub and VM compute
were ON, and native clients remained outside compute. At 20:03:26Z hub diagnostics
received direct encrypted replies from all three clients. No client or VM
lifecycle operation was performed by this task.

The old Mac's last contact had stopped at 19:54:01Z, before this coordinator
rollout. Its initial offline transition is not evidence that this patch caused
the transition. The liveness defect and fix are established by the isolated
regression tests; real sleep/shutdown/half-open fault injection remains untested.

## Release and recovery

To exclude unrelated pending changes, the release reconstructs deployed source
`eccd2c812ff604b9e6e0191736dd912b40940946` with the exact historical gateway
migration patch (SHA-256
`c4f4f5b747ddddd314ed5ef55bc81c04ab091b3158c708fe0ddd08224bfa7ca3`).
All 14 historical release-manifest hashes matched. Only coordinator `server.go`
and `presence_test.go` differ from that frozen baseline. The binary version is
`presence-20261030.1`, SHA-256
`9d15c6647464ea7ba4e487ea7fac51dfe678da9a2a5da9a9f302952bca2cfa97`.

The new image is
`docker.io/library/deepai-connect@sha256:090a332cd10eee84b42702a0568edf2a551d33dab8dd2c9e2f9bac29c7583625`.
It replaces only the binary in the pinned deployed image
`docker.io/library/deepai-connect@sha256:83a05275ebcccdfd4bbf9e6b15b97fab2a6b86dbf40ed117ad33b6710580139c`
(`gateway-api-20261018.2`). The new image is imported in the existing hub's K3s
image cache. No remote registry distribution or cold-pull recovery is qualified.

Both coordinator replicas became ready. Insufficient hub CPU initially prevented
the surge pod from scheduling, so rollout temporarily used `maxSurge: 0` and
`maxUnavailable: 1`; at least one coordinator remained ready. The original
`maxSurge: 1`, `maxUnavailable: 0` strategy was restored. Final Deployment spec
comparison showed only the image changed. IDs, addresses and key fingerprints
were preserved; the host binary, running relay/gateway and network configuration
were untouched.

The durable `deepai-system/default` NetworkState field
`spec.extensions.cluster-services-v1.Image` now references the new digest.
Only that field in the service configuration changed; no services apply operation
was invoked. Existing installed `resume`, `publish` and add-hub code read this
registry. Resume refreshes local service settings before reconciliation, so an
old local image setting does not revert the release. Missing registry state fails
closed. The host agent and normal coordinator infrastructure loop do not apply
service-image changes automatically.

Coordinator and relay share this desired Image field. A later explicit service
reconciliation will therefore also move the relay to this image, containing the
unchanged baseline relay implementation. The currently running relay was not
rolled by this repair.

To roll back, restore both the coordinator Deployment image and the durable
service Image field to `docker.io/library/deepai-connect:gateway-api-20261018.2`
(the old digest above), then verify both replicas and private connectivity.
Restore only these image references; do not restore an entire NetworkState,
delete registrations, replace keys or re-enroll clients. Rollback does not require
an application database restore. The separate App inventory repair can remain.

Sanitized build, test, deployment and preservation receipts are in
`local-setup/device-inventory-2026-10-30/` in the parent workspace, especially
`summary.json`, `connect-release/preparation.json`, `connect-rollout.json` and
`service-image-registration.json`. App inventory semantics, both-theme UI checks
and App rollback are documented in
`app-foundation/docs/device-inventory-2026-10-30.md` in the parent workspace.
