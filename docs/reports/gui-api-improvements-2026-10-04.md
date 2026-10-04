# SDL GUI and API improvements (2026-10-04)

These are ranked by impact on operators and on future clients (web GUI, CLI, MCP). Security findings are left out because the security audit thread covers them. All file references are to `main`.

| # | Improvement | Effort | Evidence |
|---|---|---|---|
| 1 | Make the API refuse a real rollover unless a dry run was done first. A dry run would return a preview id, and the real run would take that id. Add `POST /rollovers/preview`. | M | GUI: the dry-run checkbox is off by default (ui/index.html:103), and the only guard is `confirm()` (ui/app.js:505). CLI: `--all`/`--group` start a real run with no prompt (cli/main.py:648-652). |
| 2 | Add an `Idempotency-Key` header to `POST /rollovers` so a client that retries does not rotate the secrets twice. | S/M | api/app.py:635, core/models.py:372 |
| 3 | Store runs persistently, and add an SSE stream (`/rollovers/{id}/events`), `/cancel` and `/retry` for failed targets. | L | Runs are kept only in a dict in memory (core/orchestrator.py:70). The GUI and CLI both poll (ui/app.js:544, cli/main.py:662). |
| 4 | Give every list endpoint the same `{items, next_cursor}` paging, and add filters to `/rollovers` (status, actor, since, dry_run). | M | `/rollovers` has no limit (app.py:650). The GUI cuts the list to 20 on the client (ui/app.js:555). `/audit` has no cursor (app.py:688). |
| 5 | Return every error in one problem+json shape with machine-readable codes, and declare the error responses in OpenAPI. | M | MFA returns a different `detail` shape (app.py:156). SSO errors go into the URL fragment (app.py:376). |
| 6 | Generate the clients from OpenAPI (Python for the CLI and MCP, TypeScript for the GUI). Add stable `operation_id`s first. | M | Clients are written twice: `api()` (app.js) and `call()` (main.py:547). `STATUS_LABELS` and `describe_access` are duplicated (app.js:7/298, main.py:24/281). |
| 7 | Add API tokens for machine clients (`/me/tokens`), `/auth/refresh` and `/me/sessions`. MCP and CI need these. | M | Sessions are kept only in memory, and there is no refresh token (core/identity.py:14, 115). |
| 8 | Give the GUI a dashboard and navigation: overdue and failed rotations, module health, and per-system history (`/systems/{name}/rollovers`). | L | The UI is one long page of cards (ui/index.html:68-146). |
| 9 | Clean up the REST layout. Deprecate `/targets`. Use one layout for systems (they are written under `/inventory/{id}/systems/...` but read under `/systems/...`). Move `/forwarders` under `/audit`. Add `/healthz` and `/readyz`. Make `/inventory/refresh` need a write permission. | S/M | app.py:586, 606, 579, 722, 292, 599 |
| 10 | Fix GUI accessibility: an `aria-live` region for run status, labels, focus styles, table captions, and status shown as text as well as colour. | S | ui/index.html:73, 112; app.css has no focus rules. |

## Smaller items
- `wait=true` returns a still-running run with HTTP 202 when it times out, and the response gives no `Location` or `Retry-After` header.
- Audit export (CSV/NDJSON) is missing from both the API and the GUI.
- After a run, the GUI reloads the whole run list and the whole log.
