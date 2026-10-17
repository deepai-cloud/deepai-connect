# DeepAI Connect

Run one private Kubernetes cluster across your own machines. A VPS hosts the
network coordinator and public HTTPS ingress; your other devices provide compute.

## Install and use from your terminal

Download your binary, `SHA256SUMS` and `install.sh` from
[Releases](https://github.com/deepai-cloud/deepai-connect/releases), or extract the
`deepai-connect-binaries` artifact from [CI](https://github.com/deepai-cloud/deepai-connect/actions/workflows/ci.yml).
Choose `linux`, `darwin` (macOS) or `windows`, and `amd64` (Intel/AMD) or `arm64`.

On macOS/Linux, run from the download directory:

```sh
sh install.sh --from-dir .
```

Open a new terminal after installation.

On Windows, compare `Get-FileHash .\deepai-connect-windows-amd64.exe -Algorithm SHA256`
with its entry in `SHA256SUMS`, then rename it to `deepai-connect.exe` and put it
on PATH. Use `arm64` for Windows on ARM. Administration requires OpenSSH.

## Initialize the hub

Hubs and workers require Linux amd64/arm64, systemd, root, `/dev/net/tun`,
iproute2, iptables and **K3s v1.36.4+k3s1**. A Mac worker runs in a Linux VM;
Windows worker VMs remain unvalidated.

Follow [host preparation](docs/unified-connect.md#requirements) to install
Connect at `/usr/local/bin/deepai-connect` and K3s at `/usr/local/bin/k3s`.
Prepare the service image, DNS and TLS certificate before creating the hub.
Replace the example domains and image below; `187.7.75.65` is the POC VPS.

```sh
# On the VPS
sudo deepai-connect create --name hub-1 \
  --domain mesh.example.com --public-ip 187.7.75.65 \
  --relay-domain relay-1.example.com \
  --image registry.example.com/deepai-connect:VERSION \
  --tls-cert /root/fullchain.pem --tls-key /root/privkey.pem
sudo deepai-connect inspect
```

The first hub starts alone. [Add voting hubs](docs/unified-connect.md#add-another-hub)
later to reach the default target of three voters.

## Join a worker node

Install Connect and K3s on the worker using the same host preparation above.
Create a fresh invitation on the hub:

```sh
sudo deepai-connect enroll --role worker --out /root/worker-1.invite
```

Then, on the Linux worker or Linux VM, fetch the invitation and join.
That machine needs SSH access to the hub's root account:

```sh
umask 077
scp root@187.7.75.65:/root/worker-1.invite .
sudo deepai-connect join --name worker-1 --invite ./worker-1.invite
sudo deepai-connect inspect
```

Use a unique name and invitation for each node. Invitations expire after one hour.
If installation stops after saving state, fix the cause and run
`sudo deepai-connect resume`. Preserve `/var/lib/deepai-connect` and device identities.

## Manage the cluster

From your laptop, using SSH key/agent authentication:

```sh
deepai-connect setup --hub root@187.7.75.65
deepai-connect doctor
deepai-connect nodes
deepai-connect containers
```

In PowerShell, use `.\deepai-connect.exe` if the command is not on PATH.
See the [operating guide](docs/unified-connect.md) for logs, publishing and recovery.

## Do I need the Tailscale client?

Only for direct access to private IPs from your laptop: follow
[client enrollment](docs/unified-connect.md#native-clients-and-workload-routing).
SSH administration needs no Tailscale app; Linux hubs/workers embed the mesh engine.
Published HTTPS applications need only a browser. A client does not contribute compute.

## Development

With Go 1.26.9+, run `go run ./cmd/release -version VERSION` to build all six binaries.
Tagged CI builds publish binaries and checksums; build the service image separately.
Windows amd64 has a native CI check; arm64 is cross-compiled.

[Architecture](docs/architecture.md) · [Tests](docs/testing-unified.md) · [MIT license](LICENSE)
