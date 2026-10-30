---
name: deepai-connect-worker-setup
description: Set up Linux or macOS Linux-VM compute on an existing DeepAI Connect hub, including prerequisites, private enrollment, daemons and startup verification. Use for adding compute; native private access and existing-worker lifecycle have separate skills.
---

# Set up a Connect compute worker

Use the [operating guide](../../../docs/unified-connect.md) and supported CLI.
For existing workers, preserve the VM, installation directory and identity, then
use [lifecycle](../deepai-connect-lifecycle/SKILL.md). This workflow does not create
a hub or migrate its services. A native connected laptop and its compute VM are
separate registrations; preserve both.

## Target and resources

Read repository `AGENTS.md`, setup metadata and existing user authorization.
Identify the confirmed hub, intended machine, unique lowercase name (not
Multipass's `primary` VM), Linux architecture,
state directory and startup preference. Continue authorized setup without asking
again; ask only for material choices that cannot reasonably be inferred.

On a Mac inspect host CPU, RAM, free space and Multipass inventory. Check the
actual VM data volume when known. An old same-name Kubernetes node on another
computer does not establish that this Mac has that VM. Inspect an intended
existing VM with `vm status --name NAME --json` and `vm resources` before creating
anything. Do not replace a VM or shrink a disk to make setup succeed.

Choose an explicit CPU/RAM/disk grant with host and guest OS headroom. Use the
user's sizes or state a conservative assumption based on observed capacity.
Preview `deepai-connect vm create --name NAME --cpus N --memory SIZE --disk SIZE`,
then add `--apply` within authorized setup. CPU is shared execution time; disk is
sparse logical capacity, not a physical reservation.

## Prepare and enroll

1. Verify the stable desktop CLI and SSH administration. `setup --hub USER@HOST`
   saves access metadata, not membership. Preserve hub path/preferences when
   adding `--vm NAME` after creating the VM.
2. On macOS, install official Multipass if absent and verify package provenance,
   architecture, daemon and desktop-user access. If an OS administrator prompt
   needs the user, prepare the concrete installer step and let them authenticate
   locally. Never solicit passwords in chat or bypass authentication. Preserve
   the existing hypervisor driver and other VMs.
3. Create the named Ubuntu VM with the chosen grant, or prepare the intended
   bare Linux host. Inspect host inventory before guest commands: guest commands
   may start a stopped VM. Running is not cluster readiness.
4. Follow the operating guide's prerequisites and pinned Connect/K3s installation.
   Match the verified installed hub version and guest architecture. Do not deploy
   repository main or upgrade the cluster merely to add a worker. Verify checksums
   and version output; retain `/usr/local/bin/deepai-connect` for systemd. Require
   root, systemd, `/dev/net/tun`, iproute2, iptables and sysctl. Do not start a
   competing K3s service.
5. Inspect the guest for existing installation state. Resume it with the same
   directory if present. For a new worker issue one private bounded invitation
   on the confirmed hub: `sudo deepai-connect enroll --role worker --ttl 15m
   --out FILE`. A declared cloud uses the guide's named-node invitation instead.
6. Transfer that owner-only file privately, then run `sudo deepai-connect join
   --name NAME --invite FILE` inside the guest. Never print the invitation or
   put it in chat, repository, shell history or persistent cloud-init. Join may
   wait ten minutes; monitor status rather than enrolling again. Remove only
   temporary invitation copies after success, retaining saved identity/state.

An interrupted join needs inspection, correction and `resume` with the original
directory. Repeated failure is a diagnosis boundary, not permission for a new VM,
identity or broad hub services apply. Worker enrollment must not roll out
coordinator/relay images.

## Daemons and automatic startup

When requested, configure the supported mechanisms and distinguish their scope:

- **Guest Linux boot:** use `sudo deepai-connect host startup enable --json` on
  a lifecycle-capable version. Verify `host status --json` and `host startup
  status --json` in the original directory. For a compatible historical version
  lacking those commands, inspect the existing Connect-owned units, then enable
  only `deepai-connect-agent.service` and `deepai-connect-k3s.service` with
  systemctl. Verify enabled/active state and mesh-before-K3s ordering. Do not
  overwrite custom units or upgrade all nodes for a convenience command.
- **Mac user login:** run `deepai-connect vm startup enable --name NAME --json`
  as the desktop user, without sudo. Verify status and the LaunchAgent's stable
  CLI/VM target. This is a login trigger, not before-login boot. Multipass has
  its own system daemon and may independently restore running VMs.

Do not reboot, sleep, log out or stop workloads merely to test configuration
without authorization for that interruption. Report saved configuration and
active daemons separately from actual boot/login execution. Windows worker and
automatic-start runtime remain unqualified; do not invent a scheduled task.

## Verify

Use JSON plus exit status: `nodes --json`, `network --json`, `doctor`, guest
`inspect`, VM resources and startup status. Record stable identity/IP, current
K3s heartbeat/readiness, scheduling state and allocatable capacity. Native mesh
Connected and VM Running do not establish compute ON. Missing metrics stay
Unknown; offline registrations remain visible.

Within authorized setup, run a small disposable workload pinned to the new node,
with resource bounds, then remove only that owned fixture after proof. Recheck
the native VPN profile/identity/private traffic, existing devices and host route.
Report versions, resource grant, readiness, startup configuration, remaining
qualification and sanitized evidence; never keys or kubeconfig contents.

Invoke as `$deepai-connect-worker-setup`. Repository scope applies; a task in a
parent or sibling workspace may need to read this path explicitly.
