# Installation and lifecycle

Install the CLI once, select an existing worker VM, and use explicit lifecycle
commands. Installing the CLI does not enroll a device or enable automatic start.
The CLI, Linux worker, native private-network client and Gateway Node are separate
components. Gateway Node/Ollama startup is owned by the gateway installation.

## Install the CLI

Use the binary and checksum file from the same trusted release. A checksum detects
corruption; it does not establish the publisher's identity independently of the
download source. Release artifacts are not currently signed or notarized.

macOS/Linux, from the downloaded bundle:

```sh
sh install.sh --from-dir .
deepai-connect version
```

From a checkout, `sh install.sh --from-source` uses the repository's Go toolchain.
The default destination is `~/.local/bin`; reopen the terminal after PATH changes.
For Linux host services, use the stable `/usr/local/bin/deepai-connect` path from
the [host preparation guide](unified-connect.md#requirements).

Windows, from the downloaded bundle in PowerShell:

```powershell
.\install.ps1 -FromDir .
```

Reopen PowerShell after the first PATH installation, then run
`deepai-connect version`. The default Windows destination is
`%LOCALAPPDATA%\DeepAI Connect\bin`.

Follow your organization's PowerShell execution policy. OpenSSH client and
authenticated SSH access are required for administration. CLI installation does
not install a VPN, hypervisor, Linux guest, K3s or a Windows service.

Existing hub access is configured with:

```sh
deepai-connect setup --hub USER@HOST --vm EXISTING_VM
deepai-connect doctor
```

`setup` preserves unspecified preferences when rerun for the same hub. It stores
access metadata, not a device enrollment. Creating a new worker still requires
an explicit resource grant, Linux prerequisites and a private invitation; see
[worker preparation](unified-connect.md#worker-resource-grants). Recover an
existing installation with its saved identity, never by creating a replacement VM.

## Start and stop a worker VM

```sh
deepai-connect vm status --json
deepai-connect vm start
deepai-connect vm stop
```

These commands select the VM saved by `setup --vm`. Add `--name EXISTING_VM`
to select it explicitly without hub access. Start and stop affect only that named
existing Multipass VM; repeated requests for its current state are no-ops.
They do not create, delete, re-enroll or resize it. Stop requests graceful VM
shutdown and interrupts its workloads. Plan any required application shutdown
or relocation before stopping a worker.

VM `Running` means the virtual machine is running. It does not prove mesh,
Kubernetes node readiness or application availability. Check
`deepai-connect nodes --json` and `deepai-connect doctor` for cluster health.
On a non-running VM, do not invoke guest commands simply to inspect status:
Multipass guest commands can start it implicitly.

## Automatic start on macOS

```sh
deepai-connect vm startup status --json
deepai-connect vm startup enable
deepai-connect vm startup disable
```

This is a per-user **login** trigger, not machine-boot startup. Enable installs
an owned LaunchAgent for the selected VM that runs the installed CLI once at the
next login. There is no KeepAlive loop. Enable/disable does not start or stop the
VM now. Keep the CLI at its installed absolute path; disable the trigger before
removing that binary. The plist is
`~/Library/LaunchAgents/cloud.deepai.connect.vm.<VM>.plist`.
Disable removes the file for future logins; an already loaded one-shot job stays
registered until logout and an already executing start is not cancelled.
Locking/unlocking the screen is not a fresh login.

macOS may require the user to allow background items in System Settings. A saved
plist is not evidence that login execution was authorized or successful. The
command reports the available configuration/override state separately from VM
state; a real login test is a separate verification step.

Multipass has its own privileged service and may restore a previously running
VM when that service or the machine restarts. Removing Connect's login trigger
does not disable Multipass or guarantee that the VM stays off at machine boot.
Use `vm stop` explicitly when shutdown is intended. Connect does not change the
global Multipass service, other VMs, Tailscale settings, or Gateway Node/Ollama
LaunchAgents.

## Linux host services

Run these on the Linux hub or inside the worker VM, with the original state
directory and root permissions:

```sh
sudo deepai-connect host status --json
sudo deepai-connect host start
sudo deepai-connect host stop
sudo deepai-connect host startup status --json
sudo deepai-connect host startup disable
sudo deepai-connect host startup enable
```

`host start` restores the existing agent first and waits for mesh readiness
before starting K3s. `host stop` stops the K3s service before the mesh agent.
These commands manage service processes; they do not drain Kubernetes nodes or
guarantee that every existing container has exited. K3s' retained-container
behavior is preserved. For the Mac worker, `vm stop` shuts down its whole guest.
Stopping the only hub interrupts control-plane/public access and should be an
explicit operator action.

`host startup` controls **Linux machine boot**, including boot of a VM guest.
Enable/disable changes systemd enablement without changing running services.
The explicit preference survives `resume`. Without a saved preference, automatic
boot defaults to enabled, matching historical installation behavior. Externally
disabled units are reported as drift; use `host startup disable` to preserve
manual mode across resume. Manual start remains possible
with boot startup disabled. No credentials, enrollment, routes, unrelated
firewall rules or external service registrations are reset.

Modified or differently owned unit files are refused rather than overwritten.
Use `host status --json`, `inspect`, and bounded
`journalctl -u deepai-connect-agent -u deepai-connect-k3s -n 100` to investigate.
An unavailable state is an error/unknown observation, not proof the node is off.

## Rollback and uninstall

The installers retain the previous CLI binary on upgrade. To roll back the CLI:

```sh
sh install.sh --rollback
```

Windows: `.\install.ps1 -Rollback`. This rolls back the CLI executable only;
it does not restore databases, VM snapshots, cluster state or credentials.
Disable newly added login triggers before rolling back to a CLI version that
does not implement their command. Keep node versions compatible with the cluster.
An identical reinstall must not replace the useful rollback copy. Use the same
custom installation directory if one was originally selected.

Disable Connect's VM login trigger before CLI removal, then use
`sh install.sh --uninstall` or `.\install.ps1 -Uninstall`. Installer-owned binary
removal preserves client configuration, VMs, Linux host state and device
identities. Unix uninstall refuses a binary referenced by known Connect service
registrations. Removal of a Linux node/service is a separate decommissioning
operation; disabling startup is not decommissioning. PATH entries may remain
harmlessly after uninstall rather than rewriting unrelated shell configuration.

## Platform and verification boundaries

| Capability | Linux amd64/arm64 | macOS amd64/arm64 | Windows amd64/arm64 |
| --- | --- | --- | --- |
| CLI, SSH administration | Implemented | Implemented | Implemented; native amd64 CLI tested by existing CI |
| CLI installer | Shell installer | Shell installer | PowerShell installer; current-change runtime evidence is recorded separately |
| Mesh/K3s worker | Native Linux | Linux VM; existing Mac arm64 POC validated | Linux VM remains unqualified |
| Named VM start/stop/status | Multipass adapter, source tested | Multipass adapter; bounded local read/no-op checks | Portable adapter, source tested; runtime unqualified |
| Connect automatic VM start | No desktop startup adapter | User LaunchAgent at login; real login unqualified | Returns unsupported; no task/service is registered |
| Linux service start/stop/boot preference | Implemented with systemd | Same commands inside the Linux VM | Only inside a qualified Linux guest; no native Windows host service |
| Native private-network access | Separate compatible client | Separate native-client path | Documented compatible-client path; runtime unqualified |

Windows qualification needs a real Windows host with the approved Multipass
installation/driver and authenticated regular-user CLI access, an existing
Linux guest, and network/TUN/systemd/K3s verification. The currently published
[Multipass installation guide](https://canonical.com/multipass/docs/stable/how-to-guides/install-multipass/)
specifies Windows 10/11 and Virtual Machine Platform; its
[driver guide](https://canonical.com/multipass/docs/latest/explanation/driver/)
documents HCS and version-dependent legacy drivers. Do not change an existing
driver or migrate VMs automatically. Windows logon/boot automation needs native
Task Scheduler/service permission and lifecycle acceptance before shipping.
Cross-compilation and installer success do not supply that evidence.

macOS login semantics follow Apple's
[launch service guidance](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos).
Linux enablement versus running state follows
[systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).
Current-change tests and remaining runtime limits are in the
[acceptance record](lifecycle-acceptance-2026-10-26.md).

For a registered Mac login job, inspect its last result with
`launchctl print gui/$(id -u)/cloud.deepai.connect.vm.NAME`, then check VM status
and cluster health. Absence of a job before the next login is expected after
enabling; configuration does not prove execution.

## Agent workflow

Load [deepai-connect-lifecycle](../.agents/skills/deepai-connect-lifecycle/SKILL.md)
for target selection, prerequisites, structured outputs, diagnosis and recovery.
From another workspace, explicitly read that file; repository skill discovery
does not imply discovery from a sibling project or installed binary bundle.
