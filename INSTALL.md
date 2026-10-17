# Installation prompt for an AI agent

Set up DeepAI Connect on hub `187.7.75.65` and my workers. Ask only for missing
SSH access, worker details, DNS names, registry and TLS certificate/key paths.

1. Clone `https://github.com/deepai-cloud/deepai-connect.git`. Read any `AGENTS.md`
   and follow [the operating guide](docs/unified-connect.md).
2. Inspect existing installations. Preserve device identities, saved state,
   host routes and firewall rules. Use `resume` for interrupted installations.
3. Prepare Linux hosts with the guide's prerequisites and pinned K3s executable.
   Mac workers need a Linux VM. Let Connect create the K3s service.
4. Install matching Connect binaries, verify checksums, and build/push the
   service image from the same version. Ensure every node can pull it.
5. Configure hub DNS, trusted TLS and required ports. Initialize the first hub
   with `deepai-connect create`, using the guide's flags and supplied settings.
6. On the hub, run `sudo deepai-connect enroll --role worker --out /root/worker-1.invite`.
   Transfer it privately, then run `sudo deepai-connect join --name worker-1 --invite INVITE_PATH`
   on the worker. Use a fresh invitation and unique name for each node.
7. Verify each node with `sudo deepai-connect inspect`. Configure laptop access
   with `deepai-connect setup --hub USER@187.7.75.65`, then run `deepai-connect doctor`
   and `deepai-connect nodes`. Report readiness and remaining blockers; never print credentials.

Install Tailscale only for direct laptop access to private IPs. SSH administration
and Linux Connect nodes do not need a separate Tailscale app.
