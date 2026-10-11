# DeepAI Connect

Private networking and public HTTPS access on your own Linux VPS. DeepAI Connect manages Headscale/DERP for native Tailscale clients and FRPS/Caddy for HTTP services published through standard FRPC clients.

It can also be used with DeepAI Compute.

## Install

Download the Linux binary from [GitHub Releases](https://github.com/deepai-cloud/deepai-connect/releases). The VPS does not need Go. Set `VERSION` below to the exact published tag you want; `v0.3.1` is an example:

```sh
(
  set -eu
  VERSION=v0.3.1
  [ "$(uname -s)" = Linux ] || { echo "Linux is required" >&2; exit 1; }
  case "$(uname -m)" in
    x86_64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) echo "Unsupported architecture" >&2; exit 1 ;;
  esac
  download_dir=$(mktemp -d)
  trap 'rm -rf "$download_dir"' 0
  cd "$download_dir"
  asset="deepai-connect-linux-$arch"
  base="https://github.com/deepai-cloud/deepai-connect/releases/download/$VERSION"
  curl -fL --retry 3 -o "$asset" "$base/$asset"
  curl -fL --retry 3 -o SHA256SUMS "$base/SHA256SUMS"
  sha256sum --check --ignore-missing SHA256SUMS
  sudo install -m 0755 "$asset" /usr/local/bin/deepai-connect
  deepai-connect version
)
```

Each release also includes `manifest.json` with the version, target architectures, sizes and checksums.

## Build

Requires Go 1.26.9 or newer:

```sh
git clone https://github.com/deepai-cloud/deepai-connect.git
cd deepai-connect
go run ./cmd/release
```

The builder writes Linux arm64 and amd64 binaries, `manifest.json` and `SHA256SUMS` directly to `dist/`. Copy the matching `deepai-connect-linux-ARCH` to your VPS and install it with `sudo install -m 0755 deepai-connect-linux-ARCH /usr/local/bin/deepai-connect`. Use `go run ./cmd/release -version v0.3.1` to override the embedded source version.

## Run

Use a Linux VPS with public IPv4, at least 2 GiB RAM and rootful Docker. Ubuntu 24.04/26.04 supports automatic Docker installation; other distributions need Docker installed first. Configure [DNS and firewall access](docs/usage.md#prepare-the-server), then substitute your actual values:

```sh
deepai-connect up --domain mesh.example.com --public-ip 203.0.113.10 --email owner@example.com --apps app.example.com
deepai-connect status
```

Omit `--apps` for private networking only. Verify public HTTPS, then [register peers or publish an HTTP service](docs/usage.md). Docker keeps services running after the CLI exits. Resume an existing Connect installation with `deepai-connect up` under the same account and `--dir`.

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

## CI and releases

[GitHub Actions](https://github.com/deepai-cloud/deepai-connect/actions/workflows/ci.yml) checks formatting, runs vet and race tests, builds both Linux binaries and verifies their checksums on pull requests, pushes to `main`, tag pushes and manual runs. Download the build artifact from a successful workflow run to try those binaries. Docker integration tests remain opt-in and are skipped by the standard CI checks.

After merging the release changes, tag the desired commit and push the tag:

```sh
git tag v0.3.1
git push origin v0.3.1
```

Pushing a new tag creates a GitHub Release after the checks pass, attaching both binaries, `SHA256SUMS` and `manifest.json`. The exact tag, including a leading `v`, becomes the embedded version. Use tags such as `v0.3.1` or `v0.3.1-rc.1`; semantic version tags with a prerelease suffix are marked as prereleases. Tags must start with a letter or digit and contain only letters, digits, `.`, `_`, `+` or `-`, with at most 64 characters. Pull requests, branch pushes and manual runs do not publish releases.

Releases remain drafts until all assets upload successfully. Rerun a failed workflow to finish the draft; published releases are left unchanged. Untagged CI binaries use a `dev-COMMIT` version.

## License

[MIT](LICENSE), copyright 2026 deepai.cloud. Dependencies and managed services retain their own licenses.
