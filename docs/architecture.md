# Architecture

SDL's backend is an orchestrator. The core (`src/sdl/core`) loads modules,
wires them together, and runs workflows that span several of them. It never
speaks SSH, talks to a secret manager or writes a log file itself; modules do.

```
      clients: sdl CLI · web page (/ui/) · full web GUI, MCP server for LLMs (planned)
                                     │  HTTP API (FastAPI)
┌────────────────────────────────────┴───────────────────────────────────────────┐
│ core: orchestrator · inventory merge · rollover workflow · audit · permissions │
│       identity: superuser file · sign-in · sessions · TOTP · access            │
└──┬──────────┬───────────────┬────────────────┬────────────────┬────────────┬───┘
   │ audit    │ auth          │ generator      │ inventory      │ secrets    │ target
 audit.jsonl  auth.static_    generator.       inventory.store  secrets.     target.ssh_linux
   │          token           password         inventory.netbox vault        (Windows, DBs, ...)
   │          (API tokens)                     (CMDBs, ...)     (Bitwarden,
   │                                                             ...)
   ├─ forwarder: forwarder.syslog · forwarder.gelf (Graylog) · forwarder.splunk_hec
   ├─ users: users.store (local users, records of directory users)
   └─ idp: idp.ldap (AD, LDAP) · idp.oidc (Entra ID, Okta, ...) · idp.saml
```

## Modules

A module is a Python class that subclasses one of the contracts in
`sdl/core/module.py` and is registered under the `sdl.modules` entry-point
group. SDL's own modules are registered in `pyproject.toml` exactly the way a
third-party package would register its own:

```toml
[project.entry-points."sdl.modules"]
"target.my_appliance" = "my_package:MyApplianceTarget"
```

| Contract          | Must implement                                   |
|-------------------|--------------------------------------------------|
| `AuditModule`     | `write(event)`, `query(AuditQuery)`, optionally `facets()`, `verify()` |
| `AuthModule`      | `authenticate(request) -> Actor or None` (API tokens) |
| `IdentityProviderModule` | `authenticate(username, password)` (LDAP) or `begin()` / `complete()` (single sign-on); optionally `search_users()` |
| `ForwarderModule` | `send(events)`; the core queues, batches and retries |
| `GeneratorModule` | `generate(target) -> SecretStr`                  |
| `InventoryModule` | `list_systems()`; writable ones also `put_system()`, `delete_system()` |
| `SecretsModule`   | `read(path)`, `write(path, record)`, `delete(path)` |
| `TargetModule`    | `open_session(target, credential) -> TargetSession` with `preflight()`, `set_credential()`, `verify_credential()` |
| `UserStoreModule` | `list_users()`, `get_user()`, `put_user()`, `delete_user()` |

Every module also gets:

- a pydantic `Config` model; the core validates the module's section of
  `sdl.yaml` against it at load time, so a typo fails at startup, not mid-rollover;
- `start()` / `stop()` lifecycle hooks and `health()`, shown at `GET /api/v1/modules`;
- `self.context.audit`, to record its own events;
- an optional `router()` with extra API routes, mounted at
  `/api/v1/modules/<instance id>/`.

A configuration names **instances**, so the same module type can be used
twice with different settings (the integration tests run two
`target.ssh_linux` instances, one verifying with `su`, one with SSH login).

## Audit

Every action goes through the core's `AuditRecorder`:

- sign-in: every sign-in (and failure, lockout, refusal), sign-out, password
  change or reset, authenticator set-up or reset, and every user added,
  changed (before and after), provisioned, imported or removed;
- API calls: each authenticated request (`api.request`, with its query
  string), every rejected one (`api.authenticate`, `api.authorize`), and every
  request that was let in but then failed (`api.request` with outcome
  `failure` and the HTTP status);
- the system: start and stop, and any module that fails to start or stop
  (`module.start`, `module.stop`);
- inventory: every system added, changed or removed (including attempts that
  failed), every refresh, an inventory becoming unavailable and available
  again, and NetBox objects that could not be turned into systems;
- rollovers: the request, then every step for every target, then the outcome;
- forwarding: a forwarder losing and regaining its destination.

The recorder redacts anything secret-looking before an event reaches an audit
module, and **fails closed**: if no audit module accepts an event, the
workflow stops rather than act without a record. Several audit modules can be
configured; each receives every event, and the first answers queries.

`audit.jsonl` hash-chains its entries, so `sdl audit --verify` detects an
edited, deleted or reordered line. Reviewing the log (filters by system, date,
action type, user) and forwarding it to syslog, Graylog or Splunk are
described in [logs.md](logs.md).

## Access control

The core's identity service (`sdl/core/identity.py`) establishes *who* is
calling: the superuser from its file, a local user from the user-store
module, a directory or single sign-on user through an identity-provider
module, or a machine client through an auth module (API token). Providers
only say who someone is and which of their groups they belong to; the core
maps groups to SDL roles and access, so every IAM provider gets the same rules.

Two independent things then decide what a caller can do:

- **roles** (`sdl/core/permissions.py`): `admin`, `operator`, `auditor`
  (and `superuser`, held only by the superuser) grant permissions;
- **access** (`Access` in `sdl/core/models.py`): the inventory groups and
  individual systems the caller reaches, or every system. The core filters the
  inventory, rollovers, run reports and the audit log by it.

Sign-in protection (password policy, Argon2id, lockout, TOTP, sessions) is
also in the core, so a new provider cannot weaken it. See [users.md](users.md).

## Seams for what comes next

- **More identity providers** (RADIUS, Okta's own API, ...): new
  `IdentityProviderModule`s; **another user database**: a new `UserStoreModule`.
- **Configuration module**: modules come from `sdl.yaml` today
  (`sdl/core/settings.py`); a config module can supply the same `Settings`.
  Systems already come from inventory modules ([inventory.md](inventory.md)).
- **More secret managers**: new `SecretsModule`s (Bitwarden, AWS, Azure Key Vault).
- **More targets**: new `TargetModule`s (Windows local accounts, databases, API keys).
- **Clients**: the web page, the planned full web GUI and the MCP server use
  the same HTTP API as the CLI.
- **Run history** is kept in memory by the orchestrator; the audit log is the
  durable record. A persistent run store is a natural next module.
