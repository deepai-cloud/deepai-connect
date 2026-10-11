# DeepAI Connect

Private networking and public HTTPS access on your own Linux VPS. DeepAI Connect manages Headscale/DERP for native Tailscale clients and FRPS/Caddy for HTTP services published through standard FRPC clients.

It can also be used with DeepAI Compute.

## Build

Requires Go 1.26.9 or newer:

```sh
git clone https://github.com/deepai-cloud/deepai-connect.git
cd deepai-connect
go run ./cmd/release
```

The builder writes Linux arm64 and amd64 binaries, `manifest.json` and `SHA256SUMS` directly to `dist/`. Copy the matching `deepai-connect-linux-ARCH` to your VPS, rename it `deepai-connect`, and run `chmod +x deepai-connect`. The VPS does not need Go.

## Run

Use a Linux VPS with public IPv4, at least 2 GiB RAM and rootful Docker. Ubuntu 24.04/26.04 supports automatic Docker installation; other distributions need Docker installed first. Configure [DNS and firewall access](docs/usage.md#prepare-the-server), then substitute your actual values:

```sh
./deepai-connect up --domain mesh.example.com --public-ip 203.0.113.10 --email owner@example.com --apps app.example.com
./deepai-connect status
```

Omit `--apps` for private networking only. Verify public HTTPS, then [register peers or publish an HTTP service](docs/usage.md). Docker keeps services running after the CLI exits. Resume an existing Connect installation with `./deepai-connect up` under the same account and `--dir`.

Version 0.3.0 is an open-source preview for fresh Connect deployments. Earlier previews use different state and Docker namespaces; keep their binaries, state and volumes until an explicit migration is planned. See the [release notes](docs/releases/v0.3.0.md).

## Limits

This is for trusted owners: publication credentials authorize all configured domains, and the VPS terminates public HTTPS. Applications need their own authentication. A single VPS is a failure point. Automatic backup/restore, credential rotation, domain changes and redundant servers are not implemented. Public-network acceptance, offsite recovery and signed delivery remain work in progress; local tests do not establish an uptime guarantee.

## Contributing

Run the checks before opening a focused pull request:

```sh
go test -race ./...
go vet ./...
```

Include tests for changed behavior and keep private state and credentials out of commits. [Docker integration checks](docs/usage.md#integration-checks) exercise real service clients. See [architecture](docs/architecture.md) and the optional [publishing profile API](docs/edge-profile-v1.md) for implementation details.

## License

[MIT](LICENSE), copyright 2026 deepai.cloud. Dependencies and managed services retain their own licenses.
