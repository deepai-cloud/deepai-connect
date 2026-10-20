# Cloud configuration as code

Keep your network and node definitions in `cloud.yaml`. Connect administers the
bootstrap hub through its optional SSH connection; workers join through private
invitations and pull their own configuration over HTTPS. A worker needs no SSH
server, fixed public address or incoming administration connection.

See the complete [example manifest](../examples/cloud.yaml). The workflow below
uses its names, `hub-1` and `worker-one`.

## Prepare the machines and manifest

Install a matching Connect version on the administration computer and Linux
nodes, and use a service image built from that version. The binaries and image
must include cloud configuration support. Prepare K3s, DNS, firewall rules and
TLS as described in the [operating guide](unified-connect.md#requirements).
`apply` does not install or upgrade these prerequisites.

Copy the example into your configuration repository as `cloud.yaml`, replace
its domains and image, and prepare the referenced TLS files privately. File
references are relative to the YAML file, not the shell's working directory.
The example uses the POC hub at `187.7.75.65`.

The hub's `connection.ssh` accepts `user@host`. OpenSSH uses your existing SSH
configuration, keys and agent; the account must be root or have passwordless
sudo. The target needs `deepai-connect` on its administrative PATH. The manifest
and any required TLS material travel through SSH stdin. Credentials are not
placed in remote command arguments.

The manifest defines:

| Field | Meaning |
| --- | --- |
| `network.domain` | Public coordinator DNS name, reached over HTTPS |
| `network.hostCIDR`, `podCIDR`, `serviceCIDR` | Distinct host, pod and Service networks |
| `network.packetPolicyFile` | Optional path to a JSON Tailscale `FilterRule` array |
| `bootstrap.node` | Name of the first declared voting hub |
| `bootstrap.image` | Connect service image with an explicit release tag or SHA-256 digest |
| `bootstrap.voters` | Target of three or five etcd voters |
| `bootstrap.tlsCertFile`, `tlsKeyFile` | Paired TLS files, required when creating a fresh hub |
| `nodes.<name>.role` | `hub` or `worker` |
| `nodes.<name>.voter` | Whether a hub votes in etcd; workers cannot vote |
| `nodes.<name>.publicIP`, `relayDomain` | Required public IPv4 and unique relay hostname for hubs |
| `nodes.<name>.connection.ssh` | Optional administration connection for a hub |
| `nodes.<name>.labels` | Kubernetes labels managed by this manifest |

For an existing hub, both TLS path fields may be omitted together. These are
bootstrap inputs; applying the manifest does not rotate the installed TLS secret.

Node names are lowercase DNS labels. Unknown fields, duplicate YAML keys,
anchors and aliases are rejected. Label namespaces owned by Kubernetes or
Connect are reserved. A worker declaration cannot contain `connection.ssh`;
it joins locally with an invitation. Additional hubs also join using invitations;
only the bootstrap hub's SSH connection is used by `plan`, `apply` and remote
`enroll`.

The default network ranges are those in the example. The initial hub starts
alone even when `bootstrap.voters` is three. Declaring additional hubs does not
provision them or provide HA before they have joined and been qualified.

## Preview and apply

From the administration computer:

```sh
deepai-connect plan -f cloud.yaml
deepai-connect apply -f cloud.yaml
```

`plan` reads the hub and previews the configuration and enrollment state without
applying it. `apply` creates the first hub when its installation is absent,
resumes an incomplete installation with the same identity, or updates the
existing desired configuration. Declared devices initially appear as
`awaiting enrollment`.

To administer directly on the Linux bootstrap hub, copy the manifest and any
referenced files there and use:

```sh
sudo deepai-connect plan --local -f cloud.yaml
sudo deepai-connect apply --local -f cloud.yaml
```

`--local` ignores the SSH connection. If the bootstrap hub has no
`connection.ssh`, `plan` and `apply` operate locally by default.

## Invite and join a device

After applying the manifest, issue a named invitation from the administration
computer:

```sh
mkdir -p private
chmod 700 private
deepai-connect enroll -f cloud.yaml --node worker-one \
  --out ./private/worker-one.invite
```

That command contacts the declared bootstrap hub over SSH and saves the
invitation locally with private permissions. If administering on the hub
without SSH, use:

```sh
sudo deepai-connect enroll --node worker-one --out /root/worker-one.invite
```

Deliver the file to the device through a private channel. SSH is one possible
transfer method; it is not required. On the prepared Linux worker or Linux VM:

```sh
sudo deepai-connect join --invite ./worker-one.invite
sudo deepai-connect inspect
sudo deepai-connect pull --json
```

The invitation supplies the node name and role. For an additional hub it also
supplies its declared public IP and relay hostname. If these flags are supplied
explicitly to `join`, they must match the invitation.

An invitation authorizes one machine for one declared node and expires after
one hour by default (`--ttl` permits up to 24 hours). A node name alone never
authorizes enrollment. Once joined, the device uses its persistent
cryptographic identity. Repeating `apply` preserves that identity and does not
issue new invitations or reinstall devices. Recover an interrupted join with
`sudo deepai-connect resume` on the same device and state directory.

Mac workers require a prepared Linux VM. The manifest does not create VMs or
grant CPU, memory or disk; those remain local owner-controlled operations.
Native Tailscale clients use the existing `enroll --role client` flow and are
outside this manifest's hub/worker inventory.

## Change configuration

Edit and commit the manifest, then run `plan` and `apply` again. You can declare
new nodes, change node labels and update packet policy. Enroll new devices
separately.

Agents pull their own authenticated configuration immediately after startup
and every 30 seconds. `sudo deepai-connect pull --json` requests an immediate
pull and prints the saved configuration. Pulling saves `configuration.json`
under the node's installation directory; it does not restart K3s or replace
device identity. The mesh continues to receive policy through its authenticated
network maps.

The coordinator reconciles declared Kubernetes labels every 30 seconds, and
`apply` also attempts an immediate reconciliation. It verifies each enrolled
node's identity and readiness, preserves unrelated labels, and removes labels
previously managed by the manifest when they are omitted. A conflicting existing
label that the manifest does not own is rejected. If a node is unavailable or a
patch conflicts, configuration remains saved and reconciliation retries.

Omitting `network.packetPolicyFile` preserves the current packet policy. A
specified file must contain a valid JSON `FilterRule` array; an explicit `[]`
denies all mesh traffic. When that field is present, manage policy through the
manifest; the standalone `policy` command rejects an override. Enabling an
Internet gateway also preserves that declared policy, so any intended Internet
egress must be allowed explicitly in the policy file.

Changes requiring migration are rejected: installed network ranges, coordinator
domain, service image, target voter count, cloud/bootstrap identity, enrolled
hub endpoints, and enrolled node removal or role/voter changes. Removing a node
from YAML is not a decommission operation.

## Adopt an existing unified installation

Update the installed Connect binaries and deployed service image to versions
that support this workflow before adoption. This is a separate upgrade step;
`apply` rejects image changes and does not upgrade binaries.

Describe the existing bootstrap hub and **every enrolled hub and worker**, using
their exact names, roles, voter membership, hub endpoints and installed network,
image and voter settings. Run `plan`, correct any mismatch, then `apply`.
Application of the existing hub's service resources also installs the required
label-controller permissions. Existing device state is retained.

## Keep secrets and state out of Git

Commit the manifest and any referenced policy file. Add `private/` to your
configuration repository's `.gitignore` before storing TLS material or
invitations there. Delete transferred invitation copies after successful
enrollment.

Do not commit TLS private keys, invitation tokens, enrollment credentials or
`/var/lib/deepai-connect`. Back up device identities and cluster state separately.
Git is not a replacement for those backups: the YAML deliberately contains no
device identity or recovery secrets. Local mesh recovery does not wait for Git,
a configuration pull or Kubernetes.
