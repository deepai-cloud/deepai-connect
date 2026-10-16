# DeepAI Connect

One Kubernetes cluster across Linux hosts, connected by a persistent private
Tailscale-compatible overlay. Hubs provide coordination, encrypted packet relays
and public HTTPS ingress; workers run workloads. Host networking starts before
Kubernetes and restores its identity and trusted peer paths after reboot.

- [Setup and operating guide](docs/unified-connect.md): install, create, join,
  publish, route policy, Internet egress and recovery.
- [Architecture](docs/architecture.md): components, state and recovery boundaries.
- [Acceptance tests](docs/testing-unified.md).

## Install and use from your terminal

Download `deepai-connect-binaries` from a successful [CI run](https://github.com/deepai-cloud/deepai-connect/actions/workflows/ci.yml),
or choose a version from [GitHub Releases](https://github.com/deepai-cloud/deepai-connect/releases).
The bundle contains Linux and macOS binaries for Intel/AMD (`amd64`) and ARM
(`arm64`), plus `SHA256SUMS`. Apple Silicon Macs use `deepai-connect-darwin-arm64`.
No Go toolchain or Tailscale client is needed to run the downloaded command.

```sh
# From this checkout, install an extracted CI/release bundle:
sh install.sh --from-dir /path/to/downloaded-binaries
# Or download and install a published version:
sh install.sh --version VERSION
```

The installer verifies the native binary, installs it into `~/.local/bin`, and
adds that directory to your shell's PATH. Open a new terminal after installation.
macOS and Linux support administration; hubs and workers still run on Linux.
For development, `sh install.sh --from-source` builds and installs this checkout
using Go 1.26.9 or newer. `--bin-dir DIR` and `--no-path` control installation.

Connect to an existing hub using an SSH account with root or passwordless sudo:

```sh
deepai-connect setup --hub admin@hub.example.com
deepai-connect doctor
deepai-connect nodes
deepai-connect containers
deepai-connect logs POD -n NAMESPACE --tail=100
```

For a local Multipass worker, add `--vm WORKER_VM` to `setup` to include its status.
These commands use the hub's Kubernetes tools and credentials over SSH. They do
not require a local Kubernetes client or a change to your VPN or host routes.
`deepai-connect kubectl ARGS...` runs Kubernetes commands on the hub: file paths
and port-forward listeners are hub-local. Pipe a local manifest with
`deepai-connect kubectl apply -f - < app.yaml`, or use local `kubectl` with the
[installed context and tunnel](docs/unified-connect.md#laptop-administration)
for laptop-local files, copies and port forwarding.

## Build releases and install hosts

With Go 1.26.9 or newer:

```sh
go run ./cmd/release -version connect-dev
```

This writes Linux and macOS amd64/arm64 binaries, `manifest.json` and `SHA256SUMS` to
`dist/`. Copy the matching binary and checksums to each host:

```sh
sha256sum --check --ignore-missing SHA256SUMS
sudo install -m 0755 deepai-connect-linux-amd64 /usr/local/bin/deepai-connect
deepai-connect --help
```

Use the arm64 binary on ARM hosts. Hubs and workers require Linux, systemd, root,
`/dev/net/tun`, iproute2, iptables and verified **K3s v1.36.4+k3s1**. A Mac worker
runs in a Linux VM. Follow the [setup guide](docs/unified-connect.md#requirements)
for K3s installation, the service image, DNS and TLS before running `create`.

## Validate and release

```sh
go vet ./...
go test -race ./...
go test -race -tags=integration,vpsintegration ./internal/coordinator -count=1
```

[CI](https://github.com/deepai-cloud/deepai-connect/actions/workflows/ci.yml)
runs formatting, vet, race and upstream-client interoperability checks, then
builds the Linux and macOS binaries and verifies checksums. Version tags publish those
binaries, `SHA256SUMS` and `manifest.json` to
[GitHub Releases](https://github.com/deepai-cloud/deepai-connect/releases).
Releases remain drafts until every asset uploads. Build and distribute the
service image separately from the same source version.

Real Kubernetes, NAT, firewall and failure recovery tests are described in the
[acceptance procedure](docs/testing-unified.md). Local tests do not establish
independent-host or cross-region availability.

## License

[MIT](LICENSE), copyright 2026 deepai.cloud. Dependencies and managed services
retain their own licenses.
