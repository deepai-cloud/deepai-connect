---
name: deepai-connect-native-access
description: Connect or reconnect a native laptop to an existing DeepAI Connect private mesh with Tailscale, preserving profiles and verifying private access. Use for native networking, not compute enrollment, hub creation or worker lifecycle.
---

# Native private access

Use the [native-client operating guide](../../../docs/unified-connect.md#native-clients-and-workload-routing).
Desktop Connect setup configures SSH administration; it does not join the laptop
to the mesh. A native Tailscale client supplies private access and no Kubernetes
compute. Use [worker setup](../deepai-connect-worker-setup/SKILL.md) when the user
also wants workloads on this computer.

## Preserve saved profiles

Confirm the authorized hub/coordinator URL and inspect client version, current
state and saved profiles. On macOS the app CLI is commonly
`/Applications/Tailscale.app/Contents/MacOS/Tailscale`; use the actual installed
variant. Saved metadata and the confirmed hub are authority, not names inferred
from a screenshot.

If this mesh has a saved profile, select its ID and run plain `up`. Preserve other
profiles and settings. Only one native profile is active; selecting the requested
mesh changes current private access. Do not delete/reset/re-enroll to recover.
Adding `--timeout` to `up` may require repeating all nondefault flags. Retain the
settings reported by the client's consistency check instead of forcing defaults.

## First enrollment only

For authorized new access, install/start the official compatible client if
needed. Prepare any concrete OS VPN/installer approval step for the user when
required; never ask for passwords in chat or change unrelated VPN policies.

Issue one short-lived key on the confirmed hub:
`sudo deepai-connect enroll --role client --ttl 15m --out FILE`.
Transfer it privately with owner-only permissions; never print its contents.
Use the guide's OS-specific `login` with a distinct nickname/hostname, confirmed
`--login-server`, `--auth-key=file:ABSOLUTE_PATH` and `--accept-routes`. Login
creates a separate saved profile. Check partial progress before issuing a second
key. Remove temporary key copies after registration; retain the saved identity.
An expired unused key may be replaced; a registered client needs its profile,
not another invitation. The native client stays separate from a worker VM.

## Verify private traffic and startup

- Match the selected profile ID to its confirmed saved coordinator mapping.
  `status --json` and the profile list do not expose the coordinator URL. If
  that mapping is unavailable, inspect only `ControlURL` from client preferences
  using the installed client's diagnostic interface; never dump preferences or
  authentication state. Then use `status --json` for Running/identity and `ip -4`
  for the assigned address, matching the hub's registered identity.
- Client `ping` to the confirmed hub mesh address establishes encrypted direct
  or relay transport. Relay connectivity is not failure.
- Verify the OS tunnel route and a known private Service response when available.
  Ordinary IP ping alone can hit an overlapping address outside the mesh.
- Preserve saved profiles, default Internet route and unrelated routes.
  `--accept-routes` accepts approved private pod/Service routes; it does not
  authorize Internet egress or DNS changes.

Native Connected is private networking; worker compute ON requires a separate
ready/schedulable Kubernetes node. Do not delete offline registrations to make
health look current. Coordinator presence does not prove peer traffic or power.

When automatic operation is requested, inspect the native app's supported
login/reconnect preferences separately from worker startup. Configure only the
requested target. Do not replace the signed Mac VPN app with an ad hoc daemon
or claim sleep/boot/login success from a preference. Use
[lifecycle](../deepai-connect-lifecycle/SKILL.md) for worker VM login and guest
Linux boot. Windows native runtime stays unqualified until tested on that target.

Report profile/identity/IP, encrypted path, private-service result, requested
startup configuration and remaining limits. Save sanitized evidence without
keys, cookies or entire private status dumps. Invoke as
`$deepai-connect-native-access`; parent/sibling tasks may need to read its path.
