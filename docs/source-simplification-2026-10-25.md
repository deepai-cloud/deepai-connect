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
| `app-foundation` | `6f4e6487d08dfbbe9cd4120967c9d2ef270f810e`, then clean handoff `3853a9e4a597508c8949bae4d0f5b1ff3c27d630` | App orchestration/state/API and UI; the separate System UI release changed no backend source or Python tests, so the backend audit remains applicable |

The review inspected architecture/operating guides, current Git changes, CLI
dispatch, Python imports/callers, test-only protocol helpers, deployment
entrypoints, and repeated production blocks. It did not find a large dead
active feature that could safely be deleted. The user subsequently explicitly
authorized removing the obsolete local `deepai-compute` checkout and unselected
branding artifacts; that separate cleanup is recorded below. Operational evidence
in `deepai-connect-notes` remains supported.

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

Sanitized logs, per-file counts and release checksums/manifest are in workspace
`deepai-connect-notes/source-simplification-2026-10-25/`. The optional installed
Staticcheck binary could not analyze this module because it was built with Go
1.25; the required Go vet check passed.

The subsequent [remote CI run 40191370149](https://github.com/deepai-cloud/deepai-connect/actions/runs/40191370149)
completed successfully at source revision `84d491c9440b6d112338a0ef3b39365e9410bcf6`: Linux
race/stress/fuzz/interoperability, all release builds/checksums, native macOS
CLI/installer and native Windows CLI/tests passed. Release publication was
correctly skipped for this branch push. No Connect production source changed after that run.

No live VPS or Linux kernel namespace acceptance was performed. Integration tags
alone do not run the opt-in VPS test.
The refactor is source-verified, not a deployed release; existing hub/worker
identities, application state and live routes were not modified.

## Cross-project disposition

The initial candidate list was provisional. The follow-up review distinguishes
implemented work, rejected abstractions and work owned by another chat. CLI/API
entrypoints, structured output, diagnostic commands and recovery mechanisms are
supported agent surfaces even when the web UI has no caller.

| Component / candidate | Disposition | Reason and boundary |
| --- | --- | --- |
| Connect NAT installers, write-only egress flag, report-command errors, sorted map traversal | Implemented in `3844090` and `d045ef2` | Shared behavior had a smaller implementation; new contract/recovery tests also pass against the original source |
| Connect repeated Kubernetes requests (`internal/coordinator/store.go`, `internal/unified/kube.go`) | Rejected as a shared transport in this pass | The store enforces a 900 KiB request cap, 2 MiB decoding/draining and sentinel conflict/not-found errors; unified operations use merge-patch, larger decoding, smaller final draining, typed status errors and sanitized transport failures. A common policy layer erases little code while making these differences less visible |
| App Foundation HTTP clients (`backend/clients.py`) | Existing shared implementation retained | GitHub, Kubernetes, Argo and Grafana already reuse bounded HTTP transport; their ownership, retry and response semantics remain in their domain clients |
| App Foundation health-result assembly (`backend/health.py`, `Health.collect`) | Rejected as a generic result helper | Failed inventory records `None`, failed metric results remain absent, and Grafana load failure gates dependent requests. Probes, DNS and source summaries have different freshness and failure semantics. Sharing the short loops requires defaults/omission/error policy parameters rather than removing a substantial duplicate algorithm |
| App Foundation app-record writes (`backend/core.py`) | Rejected after the follow-up review; no longer deferred solely for handoff | An in-memory prototype of a private persistence helper reduced 453 lines to 451 while moving field/timestamp assignments and hiding writes behind another method. Four short writes remain explicit inside their existing transactions. The latest-attempt and old-run cleanup guards remain directly readable; the two-line saving does not justify this change |
| App Foundation desktop System frontend | Excluded from this chat's source changes; separately owned work | The System refinement owner delivered/pushed `3853a9e`; the clean checkout and unchanged backend were inspected after handoff. Its changes and line counts are not credited to this audit. No app change remains blocked on ownership |
| platformbase installation/identity/observability glue | Supported entrypoints retained; generic sharing rejected | Scripts are copied/executed independently and differ in credential/ownership behavior. A shared helper would add packaging and dependency obligations. No cross-repository utility was introduced just to reduce repeated setup lines |
| Dashboard JSON, Kubernetes manifests and tests | Retained | These are reviewable configuration and verification assets, not dead code. No minification, generator or test deletion was used to inflate reductions |
| Old local `deepai-compute` checkout | Removed under subsequent explicit cleanup authorization | Clean at `9659824`, no active dependency on its path; remote repository and active container/VM state were not deleted. Preserve separate operational/recovery evidence |

No high-value backend candidate is currently deferred solely because the app
owner is active. This is the disposition of the reviewed candidates, not proof
that no future simplification exists. A concrete change to persistence,
transport policy or standalone script packaging may justify revisiting these
small repetitions. No application API, packaged agent-skill suite or infrastructure
rollout was added to this task.

## Authorized local cleanup

On 2026-10-25 the user explicitly requested removal of the obsolete separate
Compute checkout and unselected brand variations. This superseded the earlier
retention assumption. The 67 tracked-file Compute checkout (5,487 non-test Go
lines) and its old generated distributions were removed locally; this is not
credited as a reduction of the active unified product. No replacement archive
was created and no GitHub repository was deleted. Three local Git repositories
remain: Connect, platformbase and App Foundation; the parent stays outside Git.

The brand directory now contains only selected Relay source/assets, provenance,
its exact generation prompt, font license, useful release evidence and a rebuilt
portable package. Removed: Open Workshop/Common Thread, duplicate Relay drafts,
comparison previews, the full exploration ZIP, obsolete preview tooling and two
branding-only cube/wave vault captures. Historical operational System evidence
remains. Eighteen retained original/production asset hashes are unchanged, and
the app mark/favicon match the canonical selected assets byte for byte.

The current audit's reproducible release binaries and ten Python cache directories
were also removed. Build logs, verification results, release manifest/checksums,
operational evidence, user data and current product documents remain. Measured
removal is approximately 127 MB (121 MiB) across these targets, before small new
verification records. Branding shrank from 8.7 MB to 3.1 MB including its ZIP.

The selected pack passes local HTML/Markdown/CSS links, source alpha/hash, image
metadata, ZIP CRC and packaged-file hash checks. The overview and guidelines
were visually checked at desktop size. Active repository provenance paths and
workspace/vault ownership, decision, navigation and skill pointers were updated.
These filesystem changes are local except for documentation committed in the
existing component repositories; no deployment was performed.
