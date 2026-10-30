# Agent setup skills — 2026-10-30

Connect now packages two setup workflows alongside its existing lifecycle skill:

- [Worker setup](../.agents/skills/deepai-connect-worker-setup/SKILL.md) provisions
  Linux or a Mac Linux VM on an existing hub, with an explicit resource grant,
  private enrollment, daemon/startup configuration and compute verification.
- [Native access](../.agents/skills/deepai-connect-native-access/SKILL.md) connects
  or resumes a private-network profile while preserving saved identities and
  other profiles. It does not enroll compute.
- [Lifecycle](../.agents/skills/deepai-connect-lifecycle/SKILL.md) continues to
  operate existing workers and routes new setup to the relevant package.

The README links all three. The new skills have UI metadata and allow default
automatic selection. They live under repository `.agents/skills/`; other workspaces
may need explicit paths. CLI installation alone does not install agent guidance
elsewhere. File presence, discovery in a future agent session and runtime success
are distinct; this task explicitly loaded and tested the packages.

The workflows preserve existing authorization and target identities, separate a
native Mac from its worker VM, and recover interrupted enrollment using the same
state. They check installed versions instead of upgrading the cluster to obtain
new convenience commands. For a historical guest without `host startup`, the
worker skill permits verifying and enabling only the existing owned systemd units.
Mac login, Multipass daemon behavior and Linux guest boot remain distinct.
OS authentication must happen in the local OS prompt; credentials never enter chat.

Independent forward testing used realistic compute/autostart and native-reconnect
requests. Fourteen Connect and seven native Tailscale help/version checks,
seven isolated installed-CLI scenarios and 114 race tests/subtests passed.
All three skills passed the bundled validator; relative links and diff checks
passed. Fixtures verified preview-only creation, missing/existing target refusal,
stopped VM inspection without startup, primary-VM refusal, identity-preserving
recovery, startup preference semantics and unit ownership boundaries.

The review found and corrected an evidence-source error: `status --json` and
`switch --list` do not report the coordinator URL. The native skill now requires
a confirmed profile-to-coordinator mapping (or an allowlisted ControlURL read)
and separately checks Running state, identity, encrypted transport and private
Service access. The operating guide carries the same correction.

Evidence is in `local-setup/setup-skill-forward-test-2026-10-30/` in the parent
workspace, with `report.md`, fixture results and a hash manifest. This validation
did not enroll a VM, change a native profile or execute a real boot/login.
The current Mac's separately authorized worker setup is recorded under
`local-setup/mac-compute-2026-10-30/`; runtime status must be read there rather
than inferred from skill tests. Windows worker/startup qualification remains open.
