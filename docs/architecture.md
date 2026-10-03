# Architecture

SDL's backend is an orchestrator. The core (`src/sdl/core`) loads modules,
wires them together, and runs workflows that span several of them. It never
speaks SSH, talks to a secret manager or writes a log file itself; modules do.

```
      clients: sdl CLI · web page (/ui/) · full web GUI, MCP server for LLMs (planned)
                                     │  HTTP API (FastAPI)
┌────────────────────────────────────┴───────────────────────────────────────────┐
│ core: orchestrator · inventory merge · rollover workflow · audit · permissions │
└──┬──────────┬───────────────┬────────────────┬────────────────┬────────────┬───┘
   │ audit    │ auth          │ generator      │ inventory      │ secrets    │ target
 audit.jsonl  auth.static_    generator.       inventory.store  secrets.     target.ssh_linux
              token           password         inventory.netbox vault        (Windows, DBs, ...)
              (OIDC, Entra                     (CMDBs, ...)     (Bitwarden,
               ID, ...)                                          ...)
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
| `AuditModule`     | `write(event)`, `query(...)`, optionally `verify()` |
| `AuthModule`      | `authenticate(request) -> Actor or None`         |
| `GeneratorModule` | `generate(target) -> SecretStr`                  |
| `InventoryModule` | `list_systems()`; writable ones also `put_system()`, `delete_system()` |
| `SecretsModule`   | `read(path)`, `write(path, record)`, `delete(path)` |
| `TargetModule`    | `open_session(target, credential) -> TargetSession` with `preflight()`, `set_credential()`, `verify_credential()` |

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

- API calls: each authenticated request (`api.request`) and every rejected one
  (`api.authenticate`, `api.authorize`), with the caller's identity;
- the system: start and stop;
- inventory: every system added, changed or removed, and every refresh;
- rollovers: the request, then every step for every target, then the outcome.

The recorder redacts anything secret-looking before an event reaches an audit
module, and **fails closed**: if no audit module accepts an event, the
workflow stops rather than act without a record. Several audit modules can be
configured (for example a local file and a SIEM); each receives every event.

`audit.jsonl` hash-chains its entries, so `sdl audit --verify` detects an
edited, deleted or reordered line.

## Access control

Auth modules establish *who* is calling and which roles they hold; the core
(`sdl/core/permissions.py`) decides what each role may do, so every IAM
provider gets the same rules.

| Role       | May                                              |
|------------|--------------------------------------------------|
| `admin`    | everything, including editing the inventory      |
| `operator` | run and read rollovers, list systems             |
| `auditor`  | read rollovers, list systems, read the audit log |

## Seams for what comes next

- **IAM** (OIDC/OAuth, Entra ID, ...): new `AuthModule`s; the API already
  takes its identity from whichever auth module is configured.
- **Configuration module**: modules come from `sdl.yaml` today
  (`sdl/core/settings.py`); a config module can supply the same `Settings`.
  Systems already come from inventory modules ([inventory.md](inventory.md)).
- **More secret managers**: new `SecretsModule`s (Bitwarden, AWS, Azure Key Vault).
- **More targets**: new `TargetModule`s (Windows local accounts, databases, API keys).
- **Clients**: the web page, the planned full web GUI and the MCP server use
  the same HTTP API as the CLI.
- **Run history** is kept in memory by the orchestrator; the audit log is the
  durable record. A persistent run store is a natural next module.
