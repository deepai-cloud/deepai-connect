# Source simplification — 2026-10-25

This audit implements a bounded, behavior-preserving Connect refactor. It does
not establish that every component is optimally small, remove a supported
feature, or change the live installation.

## Scope and findings

The workspace is not a Git repository. The reviewed component boundaries were:

| Component | Reviewed revision | Finding |
| --- | --- | --- |
| `deepai-connect` | `a9755e480635e7e178632b616e9f0b1475c4459a` | Unified host/cluster product; repeated NAT installation and CLI error handling can be consolidated |
| `platformbase` | `228f3d953e95fdca398983667ec9fff8cb86ba25` | Shared identity and observability; standalone installation/verification scripts and component overlays remain supported entrypoints |
| `app-foundation` | `6f4e6487d08dfbbe9cd4120967c9d2ef270f810e` | App orchestration/state/API and UI; frontend refinement was owned by another chat and excluded from this change |

The review inspected architecture/operating guides, current Git changes, CLI
dispatch, Python imports/callers, test-only protocol helpers, deployment
entrypoints, and repeated production blocks. It did not find a large dead
feature that could safely be deleted. The separate `deepai-compute` repository
and `deepai-connect-notes` remain historical evidence.

## Changes

- Gateway NAT, opted-in egress SNAT and private pod-source preservation now share
  one missing-chain/rule installer. Their exact insert/append order, protected
  destinations, source/interface restrictions and error propagation remain.
  Installation and removal share the gateway rule definition. Ownership-aware
  removal, unreachable fallback routes and firewall coexistence are unchanged.
- The `egressActive` field was only written by production code, never read.
  Removing it eliminates a redundant state variable. Recovery still inspects
  kernel routes. Its test now checks the actual route command instead of a flag.
- `network` and `nodes` share JSON flag-error handling. Schema version, error
  text, help behavior, `--` termination and explicit JSON disable remain intact.
- Declarative node/label validation and node display use the standard library's
  sorted map-key traversal, preserving deterministic validation/output order.

No new package, dependency, configuration format or public API was introduced.

## Measurement

Physical lines include comments and blank lines. Count tracked non-test Go
source plus `install.sh`; exclude tests, documentation, generated distributions,
dependency metadata and historical evidence. No vendor/generated Go source is
tracked in this repository. Build-tool source is included.

| Production source | Before | After | Net |
| --- | ---: | ---: | ---: |
| All non-test Go | 13,874 | 13,825 | −49 |
| Installer | 193 | 193 | 0 |
| **Total** | **14,067** | **14,018** | **−49** |

The 2,919 lines in the eight changed production files become 2,870. Regression
tests gain 104 lines; tests and useful documentation were not deleted to reach
the production reduction. App Foundation and platformbase have no source edits
from this audit; their concurrent owners' changes are not credited here.

## Verification

On macOS arm64 with Go 1.26.9:

- The pre-change full race suite and App Foundation's 41 Python tests passed.
- New CLI error-contract and interrupted-NAT recovery cases passed both against
  the original production source through a Go overlay and against the refactor.
  NAT tests interrupt every setup mutation, resume twice, and compare final rule
  order and unrelated rules with an uninterrupted installation.
- Formatting, `go vet ./...`, `go test -race ./...`, and five shuffled race runs
  of cloud configuration, enrollment and unified lifecycle tests passed.
- Manifest fuzzing passed for 10 seconds; local upstream Tailscale encrypted
  interoperability, including forced DERP fallback, passed with the integration
  tags used by CI.
- The release builder produced Linux, macOS and Windows amd64/arm64 binaries.
  All seven distribution checksums and native macOS version/help checks passed.

Sanitized logs, per-file counts and the local build are in workspace
`deepai-connect-notes/source-simplification-2026-10-25/`. The optional installed
Staticcheck binary could not analyze this module because it was built with Go
1.25; the required Go vet check passed.

No live VPS, Linux kernel namespace acceptance or native Windows execution was
performed in this pass. Integration tags alone do not run the opt-in VPS test.
The refactor is source-verified, not a deployed release; existing hub/worker
identities, application state and live routes were not modified.

## Further candidates and boundaries

App Foundation's repeated app-record writes could share a private persistence
helper after its current delivery boundary is released. That change needs to
retain transaction boundaries, latest-attempt status and old-run cleanup guards;
the source is already compact, so expected line savings are small.

Connect's registry and enrollment Kubernetes clients have similar request
construction but different size limits, error contracts and response-drain
budgets. Combining them offers little reduction without extra policy machinery.
Keep those differences explicit unless a concrete transport change warrants it.

Platform installation scripts repeat some Kubernetes/OIDC glue, but are copied
and executed as documented entrypoints. Any shared helper needs a complete
packaging/caller audit and credential-preservation tests. A cross-repository
utility dependency is not justified just to reduce those lines. Dashboard JSON
and Kubernetes manifests were not minified or replaced with a generator.
