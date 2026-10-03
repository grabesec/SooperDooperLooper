"""The ``sdl`` command: runs the API server, and talks to it as a client."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import time
from datetime import date, datetime, timedelta
from typing import Any
from urllib.parse import quote as _quote

import httpx

from sdl import __version__

DEFAULT_URL = "http://127.0.0.1:8800"

STATUS_LABELS = {
    "succeeded": "OK",
    "checked": "CHECKED",
    "failed": "FAILED (unchanged)",
    "rolled_back": "ROLLED BACK",
    "needs_attention": "NEEDS ATTENTION",
    "pending": "PENDING",
    "running": "RUNNING",
}


class CliError(Exception):
    pass


def quote(value: str) -> str:
    return _quote(value, safe="")


# -- server-side commands ----------------------------------------------------


def cmd_serve(args: argparse.Namespace) -> int:
    import logging

    import uvicorn

    from sdl.api.app import create_app
    from sdl.core.orchestrator import Orchestrator
    from sdl.core.settings import Settings

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logging.getLogger("asyncssh").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    app = create_app(Orchestrator(Settings.load(args.config)))
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


def cmd_check_config(args: argparse.Namespace) -> int:
    from sdl.core.orchestrator import Orchestrator
    from sdl.core.settings import Settings

    orchestrator = Orchestrator(Settings.load(args.config))
    orchestrator.load()
    print(f"{args.config}: OK")
    for instance_id, module in orchestrator.modules.items():
        print(f"  module  {instance_id:<16} {module.kind.value:<10} {type(module).__name__}")
    for target in orchestrator.targets:
        print(f"  target  {target.name:<16} {target.account}@{target.host}:{target.port}")
    return 0


def cmd_modules_available(args: argparse.Namespace) -> int:
    from sdl.core.registry import ModuleRegistry

    for name, module_cls in ModuleRegistry.from_entry_points().available().items():
        print(f"{name:<24} {module_cls.description}")
    return 0


def cmd_token_new(args: argparse.Namespace) -> int:
    from sdl.modules.auth_static_token import hash_token

    token = secrets.token_urlsafe(32)
    print(f"Token (give this to the client, it is not stored anywhere):\n  {token}\n")
    print("Add this to the static token auth module's clients in sdl.yaml:")
    print(f"  - id: {args.id}\n    token_sha256: {hash_token(token)}\n    roles: [{args.role}]")
    return 0


def cmd_token_hash(args: argparse.Namespace) -> int:
    from sdl.modules.auth_static_token import hash_token

    print(hash_token(sys.stdin.readline().strip()))
    return 0


# -- client commands -----------------------------------------------------------


def client(args: argparse.Namespace) -> httpx.Client:
    token = os.environ.get("SDL_TOKEN")
    if not token:
        raise CliError("set SDL_TOKEN to your API token")
    return httpx.Client(
        base_url=args.url, headers={"Authorization": f"Bearer {token}"}, timeout=args.http_timeout
    )


def call(http: httpx.Client, method: str, path: str, **kwargs: Any) -> Any:
    try:
        response = http.request(method, path, **kwargs)
    except httpx.HTTPError as exc:
        raise CliError(f"cannot reach SDL at {http.base_url}: {exc}") from exc
    if response.status_code >= 400:
        try:
            detail = response.json().get("detail", response.text)
        except ValueError:
            detail = response.text
        raise CliError(f"{response.status_code}: {detail}")
    if response.status_code == 204:
        return None
    return response.json()


def print_run(run: dict[str, Any], verbose: bool = False) -> None:
    kind = "dry run" if run["dry_run"] else "rollover"
    print(f"Run {run['id']} ({kind}) — {run['status'].upper()}")
    print(f"Requested by {run['requested_by']['id']}: {run['reason']}")
    print(
        f"Started {run['created_at']}"
        + (f", finished {run['finished_at']}" if run["finished_at"] else "")
    )
    print()
    rows = [("SYSTEM", "HOST", "ACCOUNT", "STATUS", "VERSION", "DETAIL")]
    for r in run["results"]:
        rows.append(
            (
                r["target"],
                r["host"],
                r["account"],
                STATUS_LABELS.get(r["status"], r["status"]),
                r["secret_version"] or "-",
                r["message"] or "",
            )
        )
    widths = [max(len(str(row[i])) for row in rows) for i in range(5)]
    for row in rows:
        print(
            "  ".join(str(c).ljust(w) for c, w in zip(row[:5], widths, strict=True)) + "  " + row[5]
        )
    if verbose:
        for r in run["results"]:
            print(f"\n{r['target']} ({r['host']}):")
            for step in r["steps"]:
                message = f" — {step['message']}" if step["message"] else ""
                print(f"  {step['ts']}  {step['name']:<14} {step['outcome']:<8}{message}")


def run_exit_code(run: dict[str, Any]) -> int:
    return 0 if run["status"] == "succeeded" else 1


def parse_selection(text: str, count: int) -> list[int]:
    """Turn ``"1,3-5"`` (1-based, as printed) into zero-based indexes; ``all`` selects every one."""
    text = text.strip().lower()
    if text in ("all", "*"):
        return list(range(count))
    chosen: list[int] = []
    for part in text.replace(" ", ",").split(","):
        if not part:
            continue
        start, _, end = part.partition("-")
        try:
            first, last = int(start), int(end or start)
        except ValueError as exc:
            raise CliError(f"not a number or range: {part!r}") from exc
        if not 1 <= first <= last <= count:
            raise CliError(f"{part!r} is outside 1-{count}")
        chosen.extend(i - 1 for i in range(first, last + 1) if i - 1 not in chosen)
    if not chosen:
        raise CliError("nothing selected")
    return chosen


def choose_systems(http: httpx.Client, args: argparse.Namespace) -> list[str]:
    """Show the inventory as a numbered list and let the user pick systems."""
    systems = fetch_systems(http, args)
    if not systems:
        raise CliError("no systems match")
    print_systems(systems, numbered=True)
    print()
    try:
        answer = input("Systems to roll over (e.g. 1,3-5 or all): ")
    except EOFError as exc:
        raise CliError("no selection given") from exc
    picked = [systems[i]["name"] for i in parse_selection(answer, len(systems))]
    print(f"Selected: {', '.join(picked)}")
    return picked


def confirm(question: str) -> bool:
    try:
        return input(f"{question} [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


def cmd_rollover_run(args: argparse.Namespace) -> int:
    with client(args) as http:
        targets = list(args.target or [])
        if args.interactive:
            targets += choose_systems(http, args)
            what = "Check" if args.dry_run else "Roll over the credential on"
            if not args.yes and not confirm(f"{what} {len(targets)} system(s) now?"):
                print("Cancelled.")
                return 1
        body = {
            "targets": targets,
            "groups": args.group or [],
            "all": args.all,
            "reason": args.reason,
            "dry_run": args.dry_run,
        }
        run = call(http, "POST", "/api/v1/rollovers", json=body)
        if not args.no_wait:
            while run["status"] in ("pending", "running"):
                time.sleep(1)
                run = call(http, "GET", f"/api/v1/rollovers/{run['id']}")
    if args.json:
        print(json.dumps(run, indent=2))
    else:
        print_run(run, args.verbose)
    return run_exit_code(run) if not args.no_wait else 0


def cmd_rollover_show(args: argparse.Namespace) -> int:
    with client(args) as http:
        run = call(http, "GET", f"/api/v1/rollovers/{args.run_id}")
    if args.json:
        print(json.dumps(run, indent=2))
    else:
        print_run(run, args.verbose)
    return run_exit_code(run)


def cmd_rollover_list(args: argparse.Namespace) -> int:
    with client(args) as http:
        runs = call(http, "GET", "/api/v1/rollovers")
    if args.json:
        print(json.dumps(runs, indent=2))
        return 0
    for run in runs:
        counts: dict[str, int] = {}
        for r in run["results"]:
            counts[r["status"]] = counts.get(r["status"], 0) + 1
        summary = ", ".join(f"{n} {s}" for s, n in sorted(counts.items()))
        print(f"{run['id']}  {run['created_at']}  {run['status']:<9}  {summary}  ({run['reason']})")
    return 0


def fetch_systems(http: httpx.Client, args: argparse.Namespace) -> list[dict[str, Any]]:
    params = {
        k: v
        for k, v in {
            "q": getattr(args, "search", None),
            "group": getattr(args, "in_group", None),
            "source": getattr(args, "source", None),
        }.items()
        if v
    }
    inventory = call(http, "GET", "/api/v1/systems", params=params)
    for source in inventory["sources"]:
        if not source["ok"]:
            print(
                f"sdl: warning: inventory {source['id']} is unavailable: {source['error']}",
                file=sys.stderr,
            )
        if source["skipped"]:
            print(
                f"sdl: warning: inventory {source['id']}: {', '.join(source['skipped'])} not "
                "listed, an earlier inventory has the same name",
                file=sys.stderr,
            )
    systems: list[dict[str, Any]] = inventory["systems"]
    return systems


def print_table(rows: list[tuple[str, ...]]) -> None:
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    for row in rows:
        print("  ".join(c.ljust(w) for c, w in zip(row, widths, strict=True)).rstrip())


def print_systems(systems: list[dict[str, Any]], numbered: bool = False) -> None:
    rows: list[tuple[str, ...]] = [
        (
            "NAME",
            "HOSTNAME",
            "FQDN",
            "IP ADDRESSES",
            "ACCOUNT",
            "SERVICE ACCOUNT",
            "GROUPS",
            "INVENTORY",
        )
    ]
    for s in systems:
        sa = s.get("service_account")
        rows.append(
            (
                s["name"],
                s.get("hostname") or "-",
                s.get("fqdn") or "-",
                ",".join(s.get("addresses") or []) or "-",
                f"{s['account']}@{s['host']}:{s['port']}",
                sa["username"] if sa else "(module default)",
                ",".join(s["groups"]) or "-",
                s.get("source") or "-",
            )
        )
    if numbered:
        rows = [("#", *rows[0])] + [(str(i), *row) for i, row in enumerate(rows[1:], start=1)]
    print_table(rows)


def cmd_systems_list(args: argparse.Namespace) -> int:
    with client(args) as http:
        systems = fetch_systems(http, args)
    if args.json:
        print(json.dumps(systems, indent=2))
    elif systems:
        print_systems(systems)
    else:
        print("no systems match", file=sys.stderr)
    return 0


def cmd_systems_show(args: argparse.Namespace) -> int:
    with client(args) as http:
        system = call(http, "GET", f"/api/v1/systems/{quote(args.name)}")
    print(json.dumps(system, indent=2) if args.json else yaml_dump(system))
    return 0


def yaml_dump(data: Any) -> str:
    import yaml

    return str(yaml.safe_dump(data, sort_keys=False)).rstrip()


def system_from_args(args: argparse.Namespace) -> dict[str, Any]:
    system: dict[str, Any] = {
        "name": args.name,
        "hostname": args.hostname,
        "fqdn": args.fqdn,
        "addresses": args.ip or [],
        "host": args.host or "",
        "port": args.port,
        "account": args.account,
        "secret_path": args.secret_path or f"linux/{args.name}/{args.account}",
        "module": args.module,
        "secrets": args.secrets,
        "groups": args.group or [],
        "description": args.description,
    }
    if args.service_account:
        if not args.service_account_path:
            raise CliError("--service-account needs --service-account-path")
        system["service_account"] = {
            "username": args.service_account,
            "credential_path": args.service_account_path,
            "credential_type": args.service_account_type,
        }
    return system


def put_system(http: httpx.Client, inventory: str, system: dict[str, Any]) -> dict[str, Any]:
    path = f"/api/v1/inventory/{quote(inventory)}/systems/{quote(str(system.get('name', '')))}"
    result: dict[str, Any] = call(http, "PUT", path, json=system)
    return result


def cmd_systems_add(args: argparse.Namespace) -> int:
    system = system_from_args(args)
    with client(args) as http:
        if not args.replace:
            response = http.get(f"/api/v1/systems/{quote(args.name)}")
            if response.status_code == 200:
                raise CliError(f"{args.name} already exists; use --replace to overwrite it")
        stored = put_system(http, args.inventory, system)
    print(f"{stored['name']}: stored in {args.inventory} (connects to {stored['host']})")
    return 0


def cmd_systems_import(args: argparse.Namespace) -> int:
    import yaml

    with open(args.file, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    systems = data.get("systems") if isinstance(data, dict) else data
    if not isinstance(systems, list):
        raise CliError(f"{args.file}: expected a list of systems (or a 'systems:' key)")
    failures = 0
    with client(args) as http:
        for system in systems:
            try:
                stored = put_system(http, args.inventory, system)
                print(f"{stored['name']}: stored in {args.inventory}")
            except CliError as exc:
                failures += 1
                print(f"{system.get('name', '?')}: {exc}", file=sys.stderr)
    return 1 if failures else 0


def cmd_systems_remove(args: argparse.Namespace) -> int:
    with client(args) as http:
        for name in args.names:
            call(http, "DELETE", f"/api/v1/inventory/{quote(args.inventory)}/systems/{quote(name)}")
            print(f"{name}: removed from {args.inventory}")
    return 0


def cmd_systems_refresh(args: argparse.Namespace) -> int:
    with client(args) as http:
        sources = call(http, "POST", "/api/v1/inventory/refresh")
    for source in sources:
        state = (
            f"{source['systems']} systems" if source["ok"] else f"UNAVAILABLE: {source['error']}"
        )
        mode = "read-write" if source["writable"] else "read-only"
        print(f"{source['id']:<16} {source['type']:<18} {mode:<10} {state}")
    return 0


_RELATIVE = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


def parse_time(text: str, *, end: bool = False) -> datetime:
    """Turn ``2026-10-01``, ``2026-10-01T14:00``, ``24h``, ``7d``, ``today`` into a time.

    Times without a zone are local. With ``end``, a bare date means the end of
    that day, so ``--until 2026-10-01`` includes all of October 1st.
    """
    value = text.strip().lower()
    now = datetime.now().astimezone()
    if value == "now":
        return now
    if value in ("today", "yesterday"):
        day = now.replace(hour=0, minute=0, second=0, microsecond=0)
        day -= timedelta(days=1 if value == "yesterday" else 0)
        return day + timedelta(days=1) if end else day
    if len(value) > 1 and value[-1] in _RELATIVE and value[:-1].isdigit():
        return now - timedelta(**{_RELATIVE[value[-1]]: int(value[:-1])})
    try:
        if len(value) == 10:
            day = datetime.combine(date.fromisoformat(value), datetime.min.time()).astimezone()
            return day + timedelta(days=1) if end else day
        parsed = datetime.fromisoformat(text.strip())
    except ValueError as exc:
        raise CliError(
            f"not a time: {text!r} (use 2026-10-01, 2026-10-01T14:00, 24h, 7d or today)"
        ) from exc
    return parsed if parsed.tzinfo else parsed.astimezone()


def audit_params(args: argparse.Namespace) -> list[tuple[str, str]]:
    params: list[tuple[str, str]] = [("limit", str(args.limit))]
    for key, values in (
        ("target", args.target),
        ("module", args.module),
        ("action", args.action),
        ("outcome", args.outcome),
        ("actor", args.actor),
    ):
        params.extend((key, v) for v in values or [])
    if args.run:
        params.append(("run_id", args.run))
    if args.since:
        params.append(("since", parse_time(args.since).isoformat()))
    if args.until:
        params.append(("until", parse_time(args.until, end=True).isoformat()))
    if args.search:
        params.append(("q", args.search))
    if args.newest_first:
        params.append(("order", "newest"))
    return params


def print_events(events: list[dict[str, Any]], verbose: bool = False) -> None:
    for e in events:
        who = f"{e['actor']['type']}:{e['actor']['id']}"
        if e.get("initiated_by"):
            who += f" for {e['initiated_by']['id']}"
        target = f" [{e['target']}]" if e.get("target") else ""
        module = f" ({e['module']})" if e.get("module") else ""
        message = f" — {e['message']}" if e.get("message") else ""
        print(f"{e['ts']}  {e['outcome']:<8} {e['action']:<32}{target}{module} {who}{message}")
        if verbose and e.get("details"):
            print("    " + json.dumps(e["details"], sort_keys=True))


def cmd_audit(args: argparse.Namespace) -> int:
    with client(args) as http:
        if args.verify:
            result = call(http, "GET", "/api/v1/audit/verify")
            print(("OK: " if result["ok"] else "TAMPERED: ") + result["detail"])
            return 0 if result["ok"] else 1
        if args.facets:
            facets = call(http, "GET", "/api/v1/audit/facets")
        else:
            events = call(http, "GET", "/api/v1/audit", params=audit_params(args))
    if args.facets:
        if args.json:
            print(json.dumps(facets, indent=2))
            return 0
        print(f"{facets['events']} events, {facets['first'] or '-'} to {facets['last'] or '-'}")
        for title, key in (
            ("Systems", "targets"),
            ("Modules", "modules"),
            ("Actors", "actors"),
            ("Actions", "actions"),
        ):
            print(f"\n{title}:")
            for value, count in sorted(facets[key].items()):
                print(f"  {value:<40} {count}")
        return 0
    if args.json:
        print(json.dumps(events, indent=2))
    elif events:
        print_events(events, args.verbose)
    else:
        print("no events match", file=sys.stderr)
    return 0


def cmd_forwarders(args: argparse.Namespace) -> int:
    with client(args) as http:
        forwarders = call(http, "GET", "/api/v1/forwarders")
    if args.json:
        print(json.dumps(forwarders, indent=2))
        return 0
    if not forwarders:
        print("no forwarder modules are configured", file=sys.stderr)
        return 0
    rows: list[tuple[str, ...]] = [
        ("FORWARDER", "STATE", "SENT", "QUEUED", "DROPPED", "LAST ERROR")
    ]
    for f in forwarders:
        rows.append(
            (
                f["id"],
                "ok" if f["ok"] else "RETRYING",
                str(f["sent"]),
                str(f["queued"]),
                str(f["dropped"]),
                f["last_error"] or "-",
            )
        )
    print_table(rows)
    return 0 if all(f["ok"] for f in forwarders) else 1


# -- argument parsing -----------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sdl", description="SooperDooperLooper secret rollovers.")
    parser.add_argument("--version", action="version", version=f"sdl {__version__}")
    parser.add_argument(
        "--url", default=os.environ.get("SDL_URL", DEFAULT_URL), help="SDL API URL (env SDL_URL)"
    )
    parser.add_argument("--http-timeout", type=float, default=60.0, help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("serve", help="run the SDL API server")
    p.add_argument("-c", "--config", default=os.environ.get("SDL_CONFIG", "sdl.yaml"))
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8800)
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("check-config", help="validate a configuration file")
    p.add_argument("-c", "--config", default=os.environ.get("SDL_CONFIG", "sdl.yaml"))
    p.set_defaults(func=cmd_check_config)

    p = sub.add_parser("modules", help="list installed module types")
    p.set_defaults(func=cmd_modules_available)

    token = sub.add_parser("token", help="manage API tokens").add_subparsers(
        dest="token_cmd", required=True
    )
    p = token.add_parser("new", help="generate a token and its config entry")
    p.add_argument("--id", required=True, help="client id recorded in the audit log")
    p.add_argument("--role", default="operator", choices=["admin", "operator", "auditor"])
    p.set_defaults(func=cmd_token_new)
    p = token.add_parser("hash", help="print the SHA-256 of a token read from stdin")
    p.set_defaults(func=cmd_token_hash)

    rollover = sub.add_parser("rollover", help="run and inspect rollovers").add_subparsers(
        dest="rollover_cmd", required=True
    )
    p = rollover.add_parser("run", help="roll over credentials now")
    p.add_argument("-t", "--target", action="append", help="system name (repeatable)")
    p.add_argument("-g", "--group", action="append", help="system group (repeatable)")
    p.add_argument("--all", action="store_true", help="every system in the inventory")
    p.add_argument(
        "-i", "--interactive", action="store_true", help="pick systems from a numbered list"
    )
    p.add_argument("--search", help="with -i: only list systems matching these words")
    p.add_argument("--in-group", help="with -i: only list systems in this group")
    p.add_argument("--source", help="with -i: only list systems from this inventory")
    p.add_argument("-y", "--yes", action="store_true", help="with -i: do not ask to confirm")
    p.add_argument("-r", "--reason", required=True, help="why; recorded in the audit log")
    p.add_argument("--dry-run", action="store_true", help="pre-flight checks only, change nothing")
    p.add_argument("--no-wait", action="store_true", help="return as soon as the run starts")
    p.add_argument("-v", "--verbose", action="store_true", help="show every step per target")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_rollover_run)
    p = rollover.add_parser("show", help="show a run's report")
    p.add_argument("run_id")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_rollover_show)
    p = rollover.add_parser("list", help="list runs")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_rollover_list)

    systems = sub.add_parser(
        "systems", help="list and manage the systems in the inventory"
    ).add_subparsers(dest="systems_cmd", required=True)
    p = systems.add_parser("list", help="list systems from every inventory")
    p.add_argument("--search", help="only systems matching these words")
    p.add_argument("-g", "--group", dest="in_group", help="only systems in this group")
    p.add_argument("--source", help="only systems from this inventory")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_systems_list)
    p = systems.add_parser("show", help="show one system")
    p.add_argument("name")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_systems_show)
    p = systems.add_parser("add", help="add a system to a writable inventory")
    p.add_argument("name")
    p.add_argument("--inventory", required=True, help="inventory module id, e.g. 'inventory'")
    p.add_argument("--hostname")
    p.add_argument("--fqdn")
    p.add_argument("--ip", action="append", help="IP address (repeatable)")
    p.add_argument("--host", help="address to connect to (default: FQDN, then first IP)")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--account", default="root", help="account whose credential is rolled over")
    p.add_argument(
        "--secret-path", help="credential's path in the secrets module (default linux/NAME/ACCOUNT)"
    )
    p.add_argument("--secrets", help="secrets module id (default: the only one)")
    p.add_argument("--module", help="target module id (default: the only one)")
    p.add_argument("--service-account", help="account SDL signs in with")
    p.add_argument(
        "--service-account-path", help="service account credential's path in the secrets module"
    )
    p.add_argument("--service-account-type", choices=["ssh_key", "password"], default="ssh_key")
    p.add_argument("-g", "--group", action="append", help="group (repeatable)")
    p.add_argument("--description")
    p.add_argument("--replace", action="store_true", help="overwrite an existing system")
    p.set_defaults(func=cmd_systems_add)
    p = systems.add_parser("import", help="add or replace systems listed in a YAML/JSON file")
    p.add_argument("file")
    p.add_argument("--inventory", required=True)
    p.set_defaults(func=cmd_systems_import)
    p = systems.add_parser("remove", help="remove systems from a writable inventory")
    p.add_argument("names", nargs="+")
    p.add_argument("--inventory", required=True)
    p.set_defaults(func=cmd_systems_remove)
    p = systems.add_parser("refresh", help="re-read every inventory (NetBox, ...)")
    p.set_defaults(func=cmd_systems_refresh)

    p = sub.add_parser("targets", help="list systems (same as 'systems list')")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_systems_list)

    p = sub.add_parser(
        "audit",
        aliases=["logs"],
        help="review, filter or verify the audit log",
        description="Show audit events; every filter given must match. "
        "Repeat a filter to match any of several values.",
    )
    p.add_argument("-t", "--target", "--system", action="append", help="system (resource) name")
    p.add_argument("-m", "--module", action="append", help="module instance id")
    p.add_argument(
        "-a",
        "--action",
        action="append",
        help="action type; 'rollover' also matches 'rollover.target.change', '*' is a wildcard",
    )
    outcomes = ["started", "success", "failure", "info", "denied"]
    p.add_argument("-o", "--outcome", action="append", choices=outcomes)
    p.add_argument(
        "-u", "--actor", "--user", action="append", help="user or component; includes on-behalf-of"
    )
    p.add_argument("--run", help="only events of this rollover run")
    p.add_argument("--since", help="from: 2026-10-01, 2026-10-01T14:00, 24h, 7d, today")
    p.add_argument("--until", help="to (a bare date includes that whole day)")
    p.add_argument("-s", "--search", help="words to find in the message")
    p.add_argument("--limit", type=int, default=200, help="most recent N matching events")
    p.add_argument("--newest-first", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true", help="show each event's details")
    p.add_argument("--facets", action="store_true", help="list the values present to filter by")
    p.add_argument("--verify", action="store_true", help="check the log's integrity")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("forwarders", help="show log forwarding status (syslog, Graylog, Splunk)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_forwarders)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except CliError as exc:
        print(f"sdl: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
