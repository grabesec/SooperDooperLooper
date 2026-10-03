# Systems and inventories

SDL needs to know, for every system it rolls over: where it is (hostname,
FQDN, IP addresses), which account's credential to roll over, where that
credential lives in the secrets module, and the service account SDL signs in
with. That information comes from **inventory modules**, so it can live in
SDL itself or in a source of truth you already run, such as NetBox.

```
 inventory.store (SDL's own) ─┐
 inventory.netbox (read-only) ─┼─> one merged list of systems ─> pick ─> rollover ─> per-system results
 targets: in sdl.yaml ─────────┘
```

## A system

| Field             | Meaning                                                                   |
|-------------------|---------------------------------------------------------------------------|
| `name`            | Unique name across all inventories                                       |
| `hostname`        | Short host name                                                           |
| `fqdn`            | Fully qualified domain name                                               |
| `addresses`       | IP addresses (IPv4 and IPv6)                                              |
| `host`            | Address SDL connects to; when empty: the FQDN, else the first IP, else the hostname |
| `port`            | SSH port (default 22)                                                     |
| `account`         | Account whose credential is rolled over (default `root`)                  |
| `secret_path`     | Where that credential lives in the secrets module                         |
| `secrets`         | Secrets module id (default: the only one configured)                      |
| `module`          | Target module id (default: the only one configured)                       |
| `service_account` | `username`, `credential_path`, `credential_type` (`ssh_key` or `password`), optional `secrets` |
| `groups`          | Labels to select systems by                                              |
| `description`     | Free text                                                                 |

**Credentials are never stored in an inventory.** A system's
`service_account.credential_path` points at the secrets module (Vault, ...),
where the service account's SSH private key or password is kept. At the start
of a rollover SDL reads it (the `service_account` step), hands it to the
target module for that one connection, and never writes it to the audit log.
A system without a `service_account` uses the target module's own configured
account (`username` and `private_key_path` in `target.ssh_linux`).

To store a service account key in Vault (KV v2, under the module's
`path_prefix`, in the module's `value_key`):

```bash
vault kv put secret/sdl/svc/sdl-svc password=@/path/to/id_ed25519
```

## SDL's own inventory: `inventory.store`

```yaml
modules:
  inventory:
    type: inventory.store
    config:
      path: /var/lib/sdl/inventory.json
```

Systems are added, changed and removed through the API, so every change is
authenticated, needs the `inventory:write` permission (the `admin` role) and
is recorded in the audit log (`inventory.system.add`, `.update`, `.delete`).
SDL checks a system can be rolled over (its target and secrets modules exist)
before storing it.

```bash
sdl systems add web1 --inventory inventory \
    --hostname web1 --fqdn web1.example.com --ip 10.0.0.11 --ip 2001:db8::11 \
    --secret-path linux/web1/root \
    --service-account sdl-svc --service-account-path svc/sdl-svc \
    --group web --group prod
sdl systems import systems.yaml --inventory inventory   # many at once
sdl systems remove web1 --inventory inventory
```

`systems.yaml` is a list of systems (or a `systems:` key holding one) with
the fields above:

```yaml
systems:
  - name: db1
    fqdn: db1.example.com
    addresses: [10.0.0.21]
    secret_path: linux/db1/root
    service_account: {username: sdl-svc, credential_path: svc/sdl-svc}
    groups: [db]
```

The web page has the same Add, Edit and Delete actions.

## NetBox: `inventory.netbox`

Reads virtual machines (and optionally devices) from NetBox. It is read-only:
NetBox stays the source of truth, SDL only adds what NetBox does not know.

```yaml
modules:
  netbox:
    type: inventory.netbox
    config:
      url: https://netbox.example.com
      token_env: NETBOX_TOKEN            # or token_file:
      objects: [virtual_machines]        # and/or devices
      filters: {status: active, tag: sdl}
      connect_via: primary_ip            # or fqdn, name
      domain: example.com                # completes short names into FQDNs
      group_by: [tags, site, role]       # tags as-is, others as "site:ams1"
      cache_ttl: 300
      defaults:
        account: root
        secret_path: "linux/{name}/{account}"
        service_account:
          username: sdl-svc
          credential_path: "svc/sdl-svc"
```

| SDL field     | From NetBox                                                          |
|---------------|----------------------------------------------------------------------|
| `name`        | the object's name                                                    |
| `hostname`    | the name up to the first dot                                         |
| `addresses`   | primary IPv4 and IPv6 address                                        |
| `fqdn`        | the primary IP's DNS name; else the name if it has a dot; else name + `domain` |
| `host`        | per `connect_via`                                                    |
| `groups`      | per `group_by`, plus `defaults.groups`                               |
| `description` | the object's description                                             |

Templates (`secret_path`, `service_account.credential_path`) may use
`{name}`, `{hostname}`, `{fqdn}`, `{account}`, `{kind}` (`vm` or `device`),
`{site}` and `{role}`. Per object, these NetBox custom fields override the
defaults: `sdl_account`, `sdl_port`, `sdl_secret_path`, `sdl_target_module`,
`sdl_service_account`, `sdl_service_account_path`.

Objects that cannot be turned into a system (no primary IP with
`connect_via: primary_ip`, for example) are skipped and listed in the
module's health (`GET /api/v1/modules`). If NetBox is unreachable, its systems
are missing from the list, the inventory is reported unavailable, and systems
from other inventories can still be rolled over.

Both token formats work: v2 tokens (`nbt_...`, NetBox 4.5+) are sent as
`Bearer`, older ones as `Token`.

## Several inventories

The list of systems is `targets:` from `sdl.yaml` first, then each inventory
module in the order it is configured. Names must be unique: when two
inventories hold the same name, the first one wins and the other is reported
as skipped, so a NetBox entry can never silently redirect a rollover. SDL
refuses to add a system to its own store under a name another inventory
already uses.

## Picking systems and seeing results

From the web page, served by the API at `http://<sdl>/ui/`: sign in with an
API token, filter the list, tick the systems, give a reason, and press *Roll
over*. The page follows the run and shows each system's status and message,
with every step behind *steps*. Recent runs can be reopened.

From the CLI:

```bash
sdl systems list --search prod --group web
sdl rollover run -i --reason "quarterly rotation"     # numbered list, pick "1,3-5"
sdl rollover run -t web1 -t db1 --reason "..."         # or by name, group, --all
sdl rollover show <run id> -v
```

Both use the same API:

| Endpoint                                              | Permission        |
|-------------------------------------------------------|-------------------|
| `GET /api/v1/systems?q=&group=&source=`               | `targets:read`    |
| `GET /api/v1/systems/{name}`                          | `targets:read`    |
| `GET /api/v1/inventory`                               | `targets:read`    |
| `POST /api/v1/inventory/refresh`                      | `targets:read`    |
| `PUT /api/v1/inventory/{inventory}/systems/{name}`    | `inventory:write` |
| `DELETE /api/v1/inventory/{inventory}/systems/{name}` | `inventory:write` |
| `POST /api/v1/rollovers` with `targets: [...]`        | `rollover:run`    |
| `GET /api/v1/rollovers/{id}`                          | `rollover:read`   |

## Writing an inventory module

Subclass `InventoryModule` (`sdl/core/module.py`), implement
`list_systems()`, and register it under the `sdl.modules` entry-point group.
Set `writable = True` and implement `put_system()` and `delete_system()` if
SDL may edit it; implement `refresh()` if it caches.
