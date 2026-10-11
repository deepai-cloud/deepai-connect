# Publishing profile v1

`deepai-connect access --out edge.json` exports the default JSON format for custom publishing integrations. Standard FRPC users can instead request a [ready-to-run client directory](usage.md#publish-an-http-service) with `--format frpc`.

| Field | Type | Required value |
| --- | --- | --- |
| `version` | integer | `1`; unsupported versions are rejected |
| `server` | string | Connect DNS hostname, also used for TLS hostname verification |
| `port` | integer | `7000` |
| `token` | string | Hex encoding of exactly 32 bytes |
| `ca` | string | One PEM self-signed CA certificate, without extra blocks or non-whitespace trailing content |
| `domains` | string array | 1–32 distinct application hostnames, excluding `server` |

Hostnames must be lowercase dotted DNS names, at most 253 characters. Labels contain 1–63 letters, digits or hyphens, without leading/trailing hyphens. IPs, wildcards and single-label names are rejected. Missing/invalid fields fail validation; unknown JSON fields are tolerated.

A consumer must verify the server's certificate against `ca` and `server`, require current CA validity before connecting, and authenticate to FRPS with `token`. Identity-only validation allows expired or not-yet-valid trust for offline inspection; it is insufficient to authorize a new connection. Connect's file helpers reject symbolic links and non-regular files and keep exports private. Keep Unix exports at mode `0600` and protect files equivalently on other platforms.

The credential grants authority for **all** listed application domains. Choosing one domain for an FRPC export does not reduce the underlying token's authority. This is trusted-owner access, without per-application tenant isolation or application authentication. The VPS terminates public HTTPS and can read HTTP traffic. Keep credentials out of source control and command arguments; replacement requires explicit maintenance. Network registration keys are separate credentials.

The [non-production fixture](../internal/contract/edgeaccess/testdata/profile-v1.json) contains a fake token and public test CA for conformance tests. Preserve v1's semantics for existing integrations; changes to interpretation or security requirements need a new schema version, migration and compatibility tests. Validate the chosen client/server versions and network path before rollout.
