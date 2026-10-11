# Usage

Run `deepai-connect` on a public **64-bit Linux VPS**. [Build the release](../README.md#build), then choose private networking, public HTTP publication, or both.

## Prepare the server

Ubuntu 24.04/26.04, public IPv4, one vCPU and at least 2 GiB RAM support a small pilot; measure relay traffic before sizing a larger deployment. Rootful Docker is required. The installer can install Docker on supported Ubuntu releases; other Linux distributions need Docker preinstalled. Use the same account and state directory throughout. Docker access is privileged access.

Create DNS-only A records for `mesh.example.com` and each application hostname, pointing to the VPS. Remove stale AAAA records unless IPv6 is configured and verified. Allow inbound TCP 80/443 and UDP 3478; allow TCP 7000 for publication clients. Restrict SSH separately. Docker publishes ports directly, so verify both provider and host firewalls. Keep unrelated management services private.

On the VPS, substitute your actual address, domains and email:

```text
./deepai-connect up --domain mesh.example.com --public-ip 203.0.113.10 --email owner@example.com --apps app.example.com,api.example.com
./deepai-connect status
```

Omit `--apps` for a private-network-only deployment. Publishing later requires application domains in the saved configuration; this preview rejects changes to existing domains, addresses and other settings rather than applying an implicit migration.

Caddy obtains public certificates after DNS and ports work. **Verify `https://mesh.example.com/health` from outside the VPS before registering peers.** Local startup checks cannot prove public DNS, firewall reachability or ACME issuance.

Docker keeps Headscale v0.29.4, its owned DERP/STUN relay, FRPS v0.71.0 and Caddy `2.11.6-alpine` running after the CLI exits. Caddy routes only configured hostnames. FRPS requires token authentication and TLS; exported clients verify the private Connect CA and hostname. The Caddy configuration disables idle read/write wrappers affected by the pinned release's regressions and retains a 30-second header timeout.

State is recorded in `connect.json` under `${XDG_CONFIG_HOME:-~/.config}/deepai/connect`. `--dir PATH` selects the exact private state directory. Plain `deepai-connect up` resumes it. Keep the account, directory, Docker engine and volumes; changing directories does not authorize adoption of orphaned containers. Domain changes, key rotation and upgrades require planned maintenance. Earlier preview installations require an explicit migration; do not point Connect at their state or recreate their containers. Retain their executable, state and volumes until a migration is planned.

## Register a private-network peer

Install a native Tailscale client and ensure its service is running on the peer. The commands below register a new, unconfigured client. For an existing account, use the native client's account-management flow to select or add this control server first. Headscale has its own identities; existing accounts are not migrated automatically.

On the VPS:

```text
./deepai-connect invite --out network.key
```

Transfer the file privately to one peer. The key is single-use and expires after one hour. Preserve Unix mode `0600`, or equivalent access restrictions on other platforms. Do not paste the key into arguments, commit it or reuse it for another peer.

On a Linux peer, replace the path with the transferred file's absolute path:

```text
sudo tailscale up --login-server=https://mesh.example.com --auth-key=file:/absolute/path/network.key
tailscale status
tailscale ip -4
```

The `file:` argument reads the secret from disk; the command line contains only its path. The same CLI flags are available to compatible native clients on other platforms with their required privileges. See the upstream [custom control server guide](https://tailscale.com/docs/how-to/set-up-custom-control-server) and [file-based authentication implementation](https://github.com/tailscale/tailscale/blob/v1.102.4/cmd/tailscale/cli/up.go).

Remove transferred key copies after successful registration. Retain the client's saved identity; ordinary reconnects use it without the consumed key. If initial registration fails because the key expired or was used, issue a fresh file. Repeat with a new key for each additional peer. The integration fixture uses Tailscale v1.102.4; validate other versions before rollout.

On one peer, use `tailscale status` to find another peer's mesh IP, then run `tailscale ping PEER_IP` with that address. Connect to services through those mesh addresses; the service must listen on an address reachable through the mesh, and its host firewall must allow access. Direct paths are preferred, with the owned DERP relay available for difficult NATs. `tailscale netcheck` helps diagnose the path. See the [Tailscale CLI reference](https://tailscale.com/docs/reference/tailscale-cli).

## Publish an HTTP service

Run an HTTP backend reachable from the machine where FRPC will run, for example `127.0.0.1:8080`. Its public hostname must already be listed in Connect's `--apps` configuration, with DNS pointing to the VPS. The publisher needs outbound TCP 7000 to the server; it does not need to join the private network.

On the VPS, export a **new** client directory:

```text
./deepai-connect access --format frpc --domain app.example.com --local-ip 127.0.0.1 --local-port 8080 --out app-client
```

The directory contains private `frpc.json`, `ca.pem` and `token` files and is never overwritten. Its parent directory must already exist. An export failure may leave a private partial directory; inspect it and remove that failed export or choose a new path before retrying. `--local-ip` must be a numeric unicast address reachable from FRPC; loopback means FRPC's own host or container. The defaults are `127.0.0.1:8080`. Transfer the complete directory privately to the publisher, preserving private permissions.

Install a standard FRPC v0.71.0 client, then run from that directory so the relative CA and token paths resolve:

```text
cd app-client
frpc verify -c frpc.json
frpc -c frpc.json
```

The bundle uses FRP's [JSON configuration](https://gofrp.org/en/docs/features/common/configure/) and [file-based token source](https://gofrp.org/en/docs/features/common/authentication/). Keep FRPC running; stopping it withdraws the tunnel, and restarting the same command restores it. Unattended operation requires your own service supervisor and access to the private directory.

Open `https://app.example.com` from a browser outside the private network. Traffic travels through Caddy and FRPS to FRPC and your backend. The VPS terminates HTTPS and sees HTTP traffic. Publication deploys no application and adds no application login. All exported bundles share Connect's publication authority across configured domains; use them only on trusted machines.

For custom integrations, `deepai-connect access --out edge.json` retains the default [profile v1 JSON export](edge-profile-v1.md). It is a credential format, not a native FRPC configuration file.

## Diagnose and recover

Run `./deepai-connect status` on the VPS, `tailscale status`/`tailscale netcheck` on peers, and inspect FRPC output on publishers. A running container or authenticated tunnel does not prove public TLS or backend health. Registration failures can mean wrong DNS/HTTPS or an expired/consumed key. Tunnel login failures can mean blocked TCP 7000, invalid CA/hostname trust or a wrong token. HTTP errors after tunnel login require a backend check from the FRPC host.

Restore original private state if a recorded container identity is missing or changed. Back up private Connect state **and** every Connect volume, including Headscale's database, Noise/DERP keys and Caddy certificate storage. Use a consistent offline backup or snapshot with services stopped; an arbitrary live SQLite-file copy is not a tested backup. Keep an encrypted copy off the VPS. Backend applications need separate backups. Automated restore and credential rotation are not implemented.

## Integration checks

The [standard checks](../README.md#contributing) run without a live server. To opt into disposable Docker fixtures:

```sh
DEEPAI_TEST_CONNECT=1 go test ./internal/connect -run TestLiveConnect -count=1
```

Fixtures use pinned images, random private domains and loopback host ports. Add `DEEPAI_TEST_CADDY_STREAM=1` for the long-idle HTTP/2 check. Public ACME, real NAT/firewall combinations, two physical networks, VPS reboot and offsite restoration still need field acceptance.
