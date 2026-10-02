"""The ``sdl`` command: runs the API server, and talks to it as a client."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import time
from typing import Any

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
    rows = [("TARGET", "HOST", "ACCOUNT", "STATUS", "VERSION", "DETAIL")]
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


def cmd_rollover_run(args: argparse.Namespace) -> int:
    body = {
        "targets": args.target or [],
        "groups": args.group or [],
        "all": args.all,
        "reason": args.reason,
        "dry_run": args.dry_run,
    }
    with client(args) as http:
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


def cmd_targets(args: argparse.Namespace) -> int:
    with client(args) as http:
        targets = call(http, "GET", "/api/v1/targets")
    if args.json:
        print(json.dumps(targets, indent=2))
        return 0
    for t in targets:
        groups = ",".join(t["groups"]) or "-"
        where = f"{t['account']}@{t['host']}:{t['port']}"
        print(f"{t['name']:<20} {where:<32} groups={groups}  secret={t['secret_path']}")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    with client(args) as http:
        if args.verify:
            result = call(http, "GET", "/api/v1/audit/verify")
            print(("OK: " if result["ok"] else "TAMPERED: ") + result["detail"])
            return 0 if result["ok"] else 1
        params = {"limit": args.limit}
        if args.run:
            params["run_id"] = args.run
        if args.target:
            params["target"] = args.target
        events = call(http, "GET", "/api/v1/audit", params=params)
    if args.json:
        print(json.dumps(events, indent=2))
        return 0
    for e in events:
        who = f"{e['actor']['type']}:{e['actor']['id']}"
        if e.get("initiated_by"):
            who += f" for {e['initiated_by']['id']}"
        target = f" [{e['target']}]" if e.get("target") else ""
        message = f" — {e['message']}" if e.get("message") else ""
        print(f"{e['ts']}  {e['outcome']:<8} {e['action']:<32}{target} {who}{message}")
    return 0


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
    p.add_argument("-t", "--target", action="append", help="target name (repeatable)")
    p.add_argument("-g", "--group", action="append", help="target group (repeatable)")
    p.add_argument("--all", action="store_true", help="every configured target")
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

    p = sub.add_parser("targets", help="list configured targets")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_targets)

    p = sub.add_parser("audit", help="read or verify the audit log")
    p.add_argument("--run", help="only events of this run")
    p.add_argument("--target", help="only events for this target")
    p.add_argument("--limit", type=int, default=200)
    p.add_argument("--verify", action="store_true", help="check the log's integrity")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_audit)
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
