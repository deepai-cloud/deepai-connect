# Architecture

The `github.com/deepai-cloud/deepai-connect` module builds the Linux arm64/amd64 `deepai-connect` CLI. Docker runs pinned Headscale, FRPS and Caddy images after each command exits; their server payloads are not embedded in the executable.

Headscale coordinates private Tailscale peers and supplies an authenticated DERP/STUN relay. Public application traffic follows HTTPS → Caddy → FRPS → authenticated TLS tunnel → FRPC → HTTP backend. These workflows are independent: FRPC publishers do not need private-network registration.

Connect exports a ready-to-run FRPC directory or a [version 1 JSON profile](edge-profile-v1.md) for custom integrations. Operators manage their client processes, application services and supervision.

| Path | Responsibility |
| --- | --- |
| `cmd/deepai-connect`, `cmd/release` | Administration CLI and release builder |
| `internal/connect` | Server configuration, lifecycle, registration and client exports |
| `internal/contract/edgeaccess` | JSON profile validation and conformance fixture |
| `internal/{runtime/docker,platform,buildinfo,architecture}` | Docker transport, private-file support, version and dependency audits |

Dependency audits cover production and test packages, permit only this module and `golang.org/x/sys` beyond the standard library, and reject module replacements. Builds ignore parent Go workspaces.

State is stored in `connect.json` under the private Connect directory. Docker resources use Connect names and labels, which are checked against saved identities before reuse. Runtime installation has a lock under the default state directory. See [operations and recovery](usage.md).

## Releases

`go run ./cmd/release` builds `dist/deepai-connect-linux-{arm64,amd64}`. Version defaults to `internal/buildinfo`; `-version` overrides it. The profile schema version is independent of the executable version.

Verify `manifest.json` and `SHA256SUMS` before distribution. The builder stages the complete release and preserves the previous output on compilation failure. Ship the binary and metadata, never private state. The builder does not upload or sign artifacts; checksums do not authenticate the publisher.
