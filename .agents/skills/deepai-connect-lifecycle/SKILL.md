---
name: deepai-connect-lifecycle
description: Install, inspect, start or stop DeepAI Connect workers and configure their automatic startup through the Connect CLI. Use for Connect CLI installation, existing Multipass worker lifecycle, Linux service startup and diagnosis; Gateway Node/Ollama and native VPN settings retain their own workflows.
---

# DeepAI Connect lifecycle

Use the installed `deepai-connect` CLI and the owning
[lifecycle guide](../../../docs/lifecycle.md). For new enrollment or interrupted
installation, read the relevant section of the
[operating guide](../../../docs/unified-connect.md). Do not recreate a worker to
fix startup. Keep its original VM, installation directory and mesh identity.

## Select the target

Distinguish the desktop CLI, a named Multipass Linux VM, Linux host services,
native Tailscale client, and Gateway Node/Ollama. Connect owns the mesh/K3s
lifecycle; this skill does not change gateway inference startup or switch the
native client's tailnet. Infer the intended target from the request and saved
configuration; clarify only if multiple targets remain plausible.

CLI install grants no enrollment or automatic startup. Use `install.sh` on
Mac/Linux or `install.ps1` on Windows with matching trusted bundle checksums;
use `--from-source`/`-FromSource` only in a source checkout with the required Go
toolchain. Preserve the stable binary path referenced by existing services.
Run `deepai-connect version` and help after installation. Installers support
CLI-only rollback and uninstall while retaining identities/configuration.

## Inspect, then perform the requested action

- Desktop worker: `deepai-connect vm status --name NAME --json`. Omit `--name`
  only when `setup --vm` already selects the intended worker. Status uses host
  Multipass inventory and does not run guest commands or start a stopped guest.
- Explicit on-demand operation: `vm start` or `vm stop`, with the same name.
  Stop interrupts this VM's workloads; a request to inspect does not authorize
  it. Start/stop preserve the VM and enrollment. Do not use force/delete/purge.
- Mac login preference: `vm startup status|enable|disable --name NAME --json`.
  Use the desktop user without sudo. It changes Connect's next-login trigger,
  not current VM state. Keep login and machine boot distinct; Multipass may
  independently restore VMs through its own service.
- Linux services: `sudo deepai-connect host status --dir DIR --json`, then
  `host start|stop` or `host startup enable|disable|status` as requested. These
  require the existing Linux installation and systemd. Start waits for mesh
  before K3s. Service stop does not drain workloads or guarantee every retained
  container exited. Boot-preference changes do not stop/start services now.

Use JSON and process exit status together. VM reports include the observed
state and whether it changed; startup reports configuration and override state.
Host reports include desired startup preference and observed per-unit states.
Failure output may describe partial progress; re-read status before retrying.
Never turn unavailable/unknown into OFF or zero capacity.

## Preconditions and diagnosis

Multipass must already be installed, its service available, and the desktop
user authorized. The Linux guest must already have Connect/K3s and its original
identity. Linux service commands require root and exact owned units; do not
overwrite a refused custom unit or bypass an ownership check. SSH administration
uses existing keys/agent and known_hosts with root or passwordless sudo on the
confirmed hub. This workflow neither issues nor renews agent credentials.

A running VM/service is not cluster readiness. Use `deepai-connect nodes --json`,
`network --json`, `doctor`, or Linux `inspect` and bounded unit journal reads.
If a start fails, retain state and diagnose the failed layer. Use `resume` only
for an incomplete/recovering installation, with its original directory. Cached
mesh recovery is independent of Kubernetes; do not re-enroll or disable unrelated
routes/firewall rules to work around a fault.

Windows CLI installation and SSH administration are distinct from worker
support. Manual VM controls have portable source tests; Windows VM runtime and
automatic startup remain unqualified. `vm startup` returns an explicit Windows
gap. Do not silently replace it with a task, service, driver change or reboot.
Use the guide's exact native-host prerequisites and acceptance checklist.

## Verify and report

Re-read the selected target after the requested mutation. For startup preference
changes, verify configuration and unchanged current running state; claim a real
boot/login success only when observed. For stop, report precisely whether a VM
shut down or only service processes stopped. Preserve unauthorized targets.

Read the [acceptance record](../../../docs/lifecycle-acceptance-2026-10-26.md)
for the current tests and runtime limits. File presence does not prove that a
particular agent session discovers this skill: explicitly read this path when
working from the shared parent or a sibling repository. Report commands,
structured outcomes, target identity and remaining verification without exposing
credentials or raw private logs.
