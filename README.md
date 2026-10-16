# DeepAI Connect

One Kubernetes cluster across Linux hosts, connected by a persistent private
Tailscale-compatible overlay. Hubs provide coordination, encrypted packet relays
and public HTTPS ingress; workers run workloads. Host networking starts before
Kubernetes and restores its identity and trusted peer paths after reboot.

- [Setup and operating guide](docs/unified-connect.md): install, create, join,
  publish, route policy, Internet egress and recovery.
- [Architecture](docs/architecture.md): components, state and recovery boundaries.
- [Acceptance tests](docs/testing-unified.md).

## Build and install

With Go 1.26.9 or newer:

```sh
go run ./cmd/release -version connect-dev
```

This writes Linux amd64/arm64 binaries, `manifest.json` and `SHA256SUMS` to
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
builds both Linux binaries and verifies checksums. Version tags publish those
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
