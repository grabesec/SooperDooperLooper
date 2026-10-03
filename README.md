# SooperDooperLooper (SDL)

SDL is an open-source tool that lets a system administrator roll over passwords,
API keys and other secrets, and proves every step of it in an audit log.

The first supported story: **roll over the root password on a handful of Linux
VMs right now.** SDL signs in to each VM with an SSH service account, changes
the password, verifies the new one actually works, stores it in HashiCorp
Vault, and hands back a per-VM report.

```
$ sdl rollover run --group web --reason "quarterly rotation"
Run 3f9c... (rollover) — SUCCEEDED
Requested by alice: quarterly rotation

SYSTEM  HOST        ACCOUNT  STATUS  VERSION  DETAIL
web1    10.0.0.11   root     OK      4        credential rolled over and verified
web2    10.0.0.12   root     OK      7        credential rolled over and verified
```

The systems SDL knows (hostnames, FQDNs, IP addresses and the service account
used for each) come from inventory modules: SDL's own store, NetBox, or both.
Sysadmins pick the systems to roll over on a web page served by SDL, or in
the CLI, and see the result for each one. See [docs/inventory.md](docs/inventory.md).

## Design

SDL's backend is an **orchestrator**: a thin core that loads modules and runs
workflows across them. Everything else is a module, and modules are
discovered through Python entry points, so third parties can ship their own.

| Kind        | Job                                           | Shipped module                                   |
|-------------|-----------------------------------------------|--------------------------------------------------|
| `audit`     | Persist every system and user action          | `audit.jsonl`: hash-chained, tamper-evident file  |
| `auth`      | Identify API callers                          | `auth.static_token`: hashed bearer tokens         |
| `generator` | Produce new credentials                       | `generator.password`: CSPRNG password policy      |
| `inventory` | Know the systems to roll over                 | `inventory.store`: SDL's own, editable via the API; `inventory.netbox`: read from NetBox |
| `secrets`   | Store credentials in a secret manager         | `secrets.vault`: HashiCorp Vault KV v2            |
| `target`    | Change and verify a credential on a system    | `target.ssh_linux`: Linux accounts over SSH       |

All clients talk to the core through its HTTP API: the bundled `sdl` CLI and
a minimal web page (at `/ui/`) today, and a full web GUI and an MCP server (so
LLMs can drive SDL) later. User management (OIDC, Entra ID, ...) arrives as
further `auth` modules.

See [docs/architecture.md](docs/architecture.md) for the module contract and
[docs/rollover.md](docs/rollover.md) for exactly what happens during a rollover
and how SDL makes sure a password is never lost.

## Quick start

Requires Python 3.11+.

```bash
pip install .            # from a checkout; installs the `sdl` command
cp examples/sdl.yaml sdl.yaml
sdl token new --id alice --role operator   # paste the printed entry into sdl.yaml
sdl check-config -c sdl.yaml
VAULT_TOKEN=... sdl serve -c sdl.yaml      # API on http://127.0.0.1:8800
```

In another shell:

```bash
export SDL_TOKEN=<the token printed by `sdl token new`>
sdl systems add web3 --inventory inventory --fqdn web3.example.com --ip 10.0.0.13 \
    --secret-path linux/web3/root            # needs an admin token
sdl systems list
sdl rollover run -i --reason "test" --dry-run      # pick systems from a numbered list
sdl rollover run --all --reason "test" --dry-run   # pre-flight only, changes nothing
sdl rollover run --all --reason "root password rotation"
sdl audit --run <run id>
sdl audit --verify
```

Or open http://127.0.0.1:8800/ in a browser, sign in with the token, tick
the systems and roll them over.

### Preparing a Linux VM

Create the service account and allow it to run `chpasswd`, and nothing else:

```bash
useradd -m -s /bin/bash sdl-svc
install -d -m 700 -o sdl-svc -g sdl-svc ~sdl-svc/.ssh
echo "<SDL's public key>" > ~sdl-svc/.ssh/authorized_keys
chown sdl-svc:sdl-svc ~sdl-svc/.ssh/authorized_keys && chmod 600 ~sdl-svc/.ssh/authorized_keys
echo 'sdl-svc ALL=(root) NOPASSWD: /usr/sbin/chpasswd' > /etc/sudoers.d/sdl-svc
chmod 440 /etc/sudoers.d/sdl-svc
```

Add each VM's host key to the `known_hosts` file SDL is configured with.

## Development

```bash
pip install -e '.[dev]'
ruff check . && ruff format --check . && mypy
pytest                                  # unit tests
SDL_INTEGRATION=1 pytest -m integration # needs Docker: dev Vault + 3 SSH test VMs
```

## License

SDL is licensed under the [GNU Affero General Public License v3.0](LICENSE).
If you run a modified SDL as a network service, you must offer its source to
its users.
