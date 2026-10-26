# Lifecycle acceptance — 26 October 2026

Scope: CLI installation/rollback/removal, named Multipass VM start/stop/status,
macOS user-login startup, and existing Linux host service/boot controls. The
[runbook](lifecycle.md) and [agent skill](../.agents/skills/deepai-connect-lifecycle/SKILL.md)
describe the supported entrypoints and remaining platform boundaries.

## Changes and preservation

- Mac/Linux installer and new Windows PowerShell installer verify bundle
  checksums, retain a previous CLI for rollback and keep configuration/identities
  on uninstall. Known service/login references prevent unsafe CLI removal.
- VM actions select an existing named VM, verify the requested resulting state,
  and return structured outcomes. Missing/unsafe/unknown state and implicit
  primary-VM creation are refused. There is no forced shutdown.
- Mac login startup owns only `cloud.deepai.connect.vm.<VM>.plist`, runs once at
  login and does not immediately start/stop the VM. Foreign/edited files and
  temporary executable paths are refused. Multipass service restoration and
  macOS background-item permission remain distinct.
- Linux commands validate saved installation and exact unit ownership, bound
  systemctl calls, order mesh before K3s on start and reverse that order on stop,
  check observed postconditions and persist boot preference across resume.
  A failed compute stop does not stop the mesh. K3s retained-container behavior
  remains explicit; service stop is not a workload drain.

The scope does not alter Gateway Node/Ollama, native mesh client configuration,
enrollment, VM resources, cluster deployments, host routes or firewall policy.
No desktop UI was changed, so new light/dark visual QA is not applicable.

## Automated checks

The repository's Go 1.26.9 toolchain is selected using
`GOTOOLCHAIN=auto GOWORK=off`; the workstation's default Go is older.

```sh
GOTOOLCHAIN=auto GOWORK=off go test -race ./...
GOTOOLCHAIN=auto GOWORK=off go vet ./...
GOTOOLCHAIN=auto GOWORK=off go run ./cmd/release -version lifecycle-20261026 -out OUTPUT
```

The full race suite and vet passed. Focused tests cover idempotency, operation
ordering, partial failures, unavailable state, ownership/symlink conflicts,
disabled boot preference through resume, no immediate mutation on startup
preference changes, retained configuration/identity and CLI installer recovery.
Native macOS `plutil` validates the generated login plist including escaped
and spaced paths, without registering it. Main-entrypoint tests verify nested
help and structured unsupported-host failures without creating host state.

The skill passed its validator. An independent source/fixture forward check of
“Check whether my existing Mac worker is configured to start automatically; do
not start it” selected the saved VM, ran only inventory and launchd override
queries, preserved a stopped VM and the login file, and created no mutation lock.
Discovery from the component repository was separately recorded by the project
knowledge owner in the vault; parent/sibling chats must explicitly read the path.

The release builder produced all six Linux/macOS/Windows amd64/arm64 binaries
and both installers; their eight checksums passed. The Windows installer and
native Windows fixture script were parsed with an official temporary PowerShell
7.6.9 runtime on macOS. The unsupported-host guard was exercised. Native Windows
installer fixtures are wired into CI but **were not run on a Windows host in
this task**. Cross-compilation is not Windows runtime acceptance.

Independent implementation review found and corrected bounded-systemctl and
installer receipt-recovery gaps. Review roles were separate from the writer;
all delegated work was followed to its final result.

## Bounded runtime evidence

Local evidence is retained at workspace
`deepai-connect-notes/lifecycle-2026-10-26/`; it contains sanitized output,
checksums and tests, not credentials or private installation files.

- The final `lifecycle-20261026` macOS arm64 release was installed at the existing
  `~/.local/bin/deepai-connect` using the checksum-verified bundle and `--no-path`.
  Version and structured status checks passed. The previous CLI's hash matches
  `.deepai-connect.previous` exactly; saved client configuration is unchanged.
- Native macOS arm64, Multipass `1.15.1+mac`, QEMU: `vm status --json` reports
  `dc-connect-mac-20261016` as Running. `vm start --json` on that already-running
  worker reports `changed:false` and does not issue a Multipass start.
- `vm startup status --json` reports `configured:false`, `enabled:false`; no
  Connect login trigger was installed or enabled for the user.
- A disposable Linux arm64 binary ran only `host status --json` inside the
  already-running worker. It validated `mac-worker-1`, phase `ready`, both units
  `active/running`, and boot enablement `enabled`. The temporary binary was
  removed. The installed Linux service binary was not replaced.
- Existing SSH administration reported both `hub-1` and `mac-worker-1` Ready.
  This is a dated observation, not a future uptime guarantee.
- Before/after comparison matched both Gateway Node/Ollama LaunchAgent file
  hashes, the worker mesh identity hash and both Linux service states. No login
  preference, worker/hub service or network configuration was changed. No
  real rollback was needed; rollback/failure recovery was exercised in fixtures.

## Remaining qualification

No real VM stop/start transition, service stop/start transition, reboot, logout,
login trigger execution, Mac sleep/wake, failure-induced live restart or Windows
runtime was performed. Existing running workloads were not interrupted for
acceptance. The login plist and systemd state checks establish configuration,
not boot/login success. macOS signing/notarization and Windows native installer,
worker driver/networking, Task Scheduler/service integration and permissions
remain unqualified; Windows automatic VM startup returns an explicit gap.

Linux fresh-install prerequisites (K3s, service image, DNS/TLS and host networking)
remain the existing operator preparation workflow. This work does not introduce
a fully unattended cross-platform worker installer or a new credential lifecycle.
Use existing authorized SSH/root/Multipass access; no enrollment bypass is added.
