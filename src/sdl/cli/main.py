"""The ``sdl`` command: runs the API server, and talks to it as a client."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets
import sys
import time
from datetime import date, datetime, timedelta
from pathlib import Path
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
    if args.group or args.system:
        print(
            f"    access: {{groups: [{', '.join(split_values(args.group or []))}], "
            f"systems: [{', '.join(split_values(args.system or []))}]}}"
        )
    return 0


def cmd_token_hash(args: argparse.Namespace) -> int:
    from sdl.modules.auth_static_token import hash_token

    print(hash_token(sys.stdin.readline().strip()))
    return 0


def read_password(prompt: str, *, confirm: bool = True, stdin: bool = False) -> str:
    """Ask for a password without echoing it (or read one line from stdin, for scripts)."""
    if stdin:
        return sys.stdin.readline().rstrip("\n")
    password = getpass.getpass(f"{prompt}: ")
    if confirm and getpass.getpass(f"{prompt} (again): ") != password:
        raise CliError("the passwords do not match")
    return password


def cmd_superuser_set(args: argparse.Namespace) -> int:
    from pydantic import SecretStr, ValidationError

    from sdl.core import passwords, superuser, totp

    path = Path(args.file)
    current = None
    if path.exists():
        current = superuser.load(path)
    if current is None and not args.name:
        raise CliError("--name is needed to create the superuser file")
    name = (args.name or (current.name if current else "")).strip().lower()
    if args.keep_password:
        if current is None:
            raise CliError("there is no password to keep yet")
        password_hash = current.password_hash
    else:
        password = read_password("Superuser password", stdin=args.password_stdin)
        try:
            passwords.check_policy(password, args.min_length, name=name)
        except passwords.PasswordPolicyError as exc:
            raise CliError(str(exc)) from exc
        password_hash = passwords.hash_password(password)
    totp_secret = current.totp_secret if current else None
    new_totp = None
    if args.no_totp:
        totp_secret = None
    elif args.totp:
        new_totp = totp.new_secret()
        print("Add this account to an authenticator app, then enter the code it shows.")
        print(f"  Secret: {new_totp}")
        print(f"  Link:   {totp.provisioning_uri(new_totp, name)}")
        code = input("Code: ").strip()
        if totp.verify(new_totp, code) is None:
            raise CliError("that code is not right; nothing was changed")
        totp_secret = SecretStr(new_totp)
    try:
        record = superuser.Superuser(
            name=name,
            display_name=args.display_name or (current.display_name if current else None),
            password_hash=password_hash,
            totp_secret=totp_secret,
        )
    except ValidationError as exc:
        raise CliError(f"invalid superuser name {name!r}") from exc
    superuser.save(path, record)
    mfa = "with" if totp_secret else "without"
    print(f"{path}: superuser {name!r} saved ({mfa} TOTP); sessions of the superuser have ended")
    return 0


def cmd_superuser_show(args: argparse.Namespace) -> int:
    from sdl.core import superuser

    record = superuser.load(Path(args.file))
    print(f"name:       {record.name}")
    print(f"TOTP:       {'yes' if record.totp_secret else 'no'}")
    print(f"updated at: {record.updated_at.isoformat()}")
    return 0


# -- client commands -----------------------------------------------------------


def session_file() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(Path.home(), ".config")
    return Path(base) / "sdl" / "session.json"


def saved_session(url: str) -> str | None:
    try:
        data = json.loads(session_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if data.get("url") != url.rstrip("/"):
        return None
    token = data.get("token")
    return token if isinstance(token, str) else None


def save_session(url: str, token: str, user: str) -> None:
    path = session_file()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({"url": url.rstrip("/"), "token": token, "user": user}, fh)


def client(args: argparse.Namespace) -> httpx.Client:
    token = os.environ.get("SDL_TOKEN") or saved_session(args.url)
    if not token:
        raise CliError("sign in with 'sdl login', or set SDL_TOKEN to an API token")
    return httpx.Client(
        base_url=args.url, headers={"Authorization": f"Bearer {token}"}, timeout=args.http_timeout
    )


def anonymous(args: argparse.Namespace) -> httpx.Client:
    return httpx.Client(base_url=args.url, timeout=args.http_timeout)


def print_pending(pending: list[str]) -> None:
    if "password_change" in pending:
        print("You must choose a new password first: run 'sdl passwd'.")
    if "mfa_enrollment" in pending:
        print("You must set up an authenticator app first: run 'sdl mfa setup'.")


def cmd_login(args: argparse.Namespace) -> int:
    with anonymous(args) as http:
        if args.sso:
            start = f"{args.url.rstrip('/')}/api/v1/auth/sso/{quote(args.sso)}/start?return_to=cli"
            print(f"Open this address in a browser and sign in:\n  {start}\n")
            code = input("Then paste the code the page shows: ").strip()
            result = call(http, "POST", "/api/v1/auth/sso/exchange", json={"code": code})
        else:
            username = args.user or input("User name: ").strip()
            password = read_password("Password", confirm=False, stdin=args.password_stdin)
            body: dict[str, Any] = {
                "username": username,
                "password": password,
                "provider": args.provider,
                "code": args.code,
            }
            response = http.post("/api/v1/auth/login", json=body)
            detail = _detail(response)
            if (
                response.status_code == 401
                and isinstance(detail, dict)
                and detail.get("mfa_required")
            ):
                body["code"] = input("Code from your authenticator app: ").strip()
                response = http.post("/api/v1/auth/login", json=body)
            if response.status_code >= 400:
                raise CliError(f"{response.status_code}: {_message(_detail(response))}")
            result = response.json()
    actor = result["actor"]
    save_session(args.url, result["token"], actor["id"])
    print(f"Signed in as {actor['id']} until {result['expires_at']}.")
    print_pending(result.get("pending", []))
    return 0


def _detail(response: httpx.Response) -> Any:
    try:
        return response.json().get("detail", response.text)
    except ValueError:
        return response.text


def _message(detail: Any) -> str:
    return str(detail.get("message", detail)) if isinstance(detail, dict) else str(detail)


def cmd_logout(args: argparse.Namespace) -> int:
    if saved_session(args.url):
        with client(args) as http:
            try:
                call(http, "POST", "/api/v1/auth/logout")
            except CliError:
                pass  # already ended on the server
    session_file().unlink(missing_ok=True)
    print("Signed out.")
    return 0


def describe_access(access: dict[str, Any] | None) -> str:
    if access is None or access.get("all_systems"):
        return "all systems"
    parts = [f"group {g}" for g in access.get("groups", [])]
    parts += [f"system {s}" for s in access.get("systems", [])]
    return ", ".join(parts) or "no systems"


def cmd_whoami(args: argparse.Namespace) -> int:
    with client(args) as http:
        me = call(http, "GET", "/api/v1/me")
    if args.json:
        print(json.dumps(me, indent=2))
        return 0
    actor = me["actor"]
    print(
        f"user:         {actor['id']}"
        + (f" ({actor['display_name']})" if actor.get("display_name") else "")
    )
    print(f"signed in:    {me.get('signed_in_with') or 'API token'}")
    print(f"roles:        {', '.join(actor['roles']) or '-'}")
    print(f"reaches:      {describe_access(me.get('access'))}")
    print(f"permissions:  {', '.join(me['permissions'])}")
    print(f"TOTP:         {'yes' if me.get('mfa') else 'no'}")
    print_pending(me.get("pending", []))
    return 0


def cmd_passwd(args: argparse.Namespace) -> int:
    current = read_password("Current password", confirm=False)
    new = read_password("New password")
    with client(args) as http:
        call(
            http,
            "POST",
            "/api/v1/me/password",
            json={"current_password": current, "new_password": new},
        )
    print("Password changed; your other sessions have ended.")
    return 0


def cmd_mfa_setup(args: argparse.Namespace) -> int:
    with client(args) as http:
        enrollment = call(http, "POST", "/api/v1/me/mfa/totp")
        print("Add this account to an authenticator app (scan the link as a QR code, or type")
        print("the secret in), then enter the code it shows.")
        print(f"  Secret: {enrollment['secret']}")
        print(f"  Link:   {enrollment['uri']}")
        code = input("Code: ").strip()
        call(http, "POST", "/api/v1/me/mfa/totp/confirm", json={"code": code})
    print("Authenticator set up: SDL will ask for a code at every sign-in.")
    return 0


def access_from_args(
    args: argparse.Namespace, current: dict[str, Any] | None = None
) -> dict[str, Any] | None:
    """Build the ``access`` of a user from --group/--system/--all-systems (and add/remove)."""
    replace = args.group is not None or args.system is not None
    changes = any(
        getattr(args, k, None) for k in ("add_group", "remove_group", "add_system", "remove_system")
    )
    if not (replace or changes or args.all_systems is not None):
        return None
    access = dict(current or {"all_systems": False, "groups": [], "systems": []})
    if args.group is not None:
        access["groups"] = split_values(args.group)
    if args.system is not None:
        access["systems"] = split_values(args.system)
    for key, add, remove in (
        ("groups", getattr(args, "add_group", None), getattr(args, "remove_group", None)),
        ("systems", getattr(args, "add_system", None), getattr(args, "remove_system", None)),
    ):
        values = [v for v in access[key] if v not in split_values(remove or [])]
        access[key] = values + [v for v in split_values(add or []) if v not in values]
    if args.all_systems is not None:
        access["all_systems"] = args.all_systems
    return access


def split_values(values: list[str]) -> list[str]:
    return [v.strip() for value in values for v in value.split(",") if v.strip()]


def print_users(users: list[dict[str, Any]]) -> None:
    rows: list[tuple[str, ...]] = [
        ("NAME", "DISPLAY NAME", "SOURCE", "STATE", "ROLES", "REACHES", "TOTP", "LAST SIGN-IN")
    ]
    for u in users:
        state = "enabled" if u["enabled"] else "DISABLED"
        if u["must_change_password"]:
            state += ", must change password"
        rows.append(
            (
                u["name"],
                u.get("display_name") or "-",
                u["source"],
                state,
                ",".join(u["roles"]) or "-",
                describe_access(u["access"]),
                "yes" if u["mfa"] else "no",
                u.get("last_login") or "never",
            )
        )
    print_table(rows)


def cmd_users_list(args: argparse.Namespace) -> int:
    with client(args) as http:
        users = call(http, "GET", "/api/v1/users")
    if args.json:
        print(json.dumps(users, indent=2))
    elif users:
        print_users(users)
    else:
        print("no users yet; add one with 'sdl users add'", file=sys.stderr)
    return 0


def cmd_users_show(args: argparse.Namespace) -> int:
    with client(args) as http:
        user = call(http, "GET", f"/api/v1/users/{quote(args.name)}")
    print(json.dumps(user, indent=2) if args.json else yaml_dump(user))
    return 0


def cmd_users_add(args: argparse.Namespace) -> int:
    body: dict[str, Any] = {
        "name": args.name,
        "display_name": args.display_name,
        "email": args.email,
        "roles": split_values(args.role or []),
        "access": access_from_args(args) or {},
        "enabled": not args.disabled,
    }
    if not args.no_password:
        body["password"] = read_password(
            f"Initial password for {args.name}", stdin=args.password_stdin
        )
    with client(args) as http:
        user = call(http, "POST", "/api/v1/users", json=body)
    print(
        f"{user['name']}: added ({', '.join(user['roles']) or 'no roles'}; reaches "
        f"{describe_access(user['access'])})"
    )
    if user["must_change_password"]:
        print("They must choose a new password at first sign-in.")
    return 0


def cmd_users_set(args: argparse.Namespace) -> int:
    with client(args) as http:
        current = call(http, "GET", f"/api/v1/users/{quote(args.name)}")
        body: dict[str, Any] = {}
        roles = list(current["roles"])
        if args.role is not None:
            roles = split_values(args.role)
        roles = [r for r in roles if r not in split_values(args.remove_role or [])]
        roles += [r for r in split_values(args.add_role or []) if r not in roles]
        if roles != current["roles"]:
            body["roles"] = roles
        access = access_from_args(args, current["access"])
        if access is not None:
            body["access"] = access
        if args.enabled is not None:
            body["enabled"] = args.enabled
        for key in ("display_name", "email"):
            if getattr(args, key) is not None:
                body[key] = getattr(args, key)
        if not body:
            raise CliError("nothing to change")
        user = call(http, "PATCH", f"/api/v1/users/{quote(args.name)}", json=body)
    print_users([user])
    return 0


def cmd_users_remove(args: argparse.Namespace) -> int:
    with client(args) as http:
        for name in args.names:
            call(http, "DELETE", f"/api/v1/users/{quote(name)}")
            print(f"{name}: removed")
    return 0


def cmd_users_password(args: argparse.Namespace) -> int:
    password = read_password(f"New password for {args.name}", stdin=args.password_stdin)
    with client(args) as http:
        call(
            http,
            "POST",
            f"/api/v1/users/{quote(args.name)}/password",
            json={"password": password, "temporary": not args.permanent},
        )
    then = "" if args.permanent else "; they must change it at next sign-in"
    print(f"{args.name}: password set{then}")
    return 0


def cmd_users_reset_mfa(args: argparse.Namespace) -> int:
    with client(args) as http:
        call(http, "DELETE", f"/api/v1/users/{quote(args.name)}/mfa")
    print(f"{args.name}: authenticator removed; they can set up a new one after signing in")
    return 0


def cmd_users_unlock(args: argparse.Namespace) -> int:
    with client(args) as http:
        call(http, "POST", f"/api/v1/users/{quote(args.name)}/unlock")
    print(f"{args.name}: unlocked")
    return 0


def cmd_users_search(args: argparse.Namespace) -> int:
    with client(args) as http:
        found = call(
            http,
            "GET",
            f"/api/v1/idps/{quote(args.provider)}/users",
            params={"q": args.query, "limit": args.limit},
        )
    if args.json:
        print(json.dumps(found, indent=2))
        return 0
    rows: list[tuple[str, ...]] = [("USER NAME", "DISPLAY NAME", "EMAIL", "GROUPS")]
    for u in found:
        rows.append(
            (
                u["username"],
                u.get("display_name") or "-",
                u.get("email") or "-",
                ",".join(u["groups"]) or "-",
            )
        )
    print_table(rows)
    return 0


def cmd_users_import(args: argparse.Namespace) -> int:
    body = {
        "username": args.username,
        "roles": split_values(args.role or []),
        "access": access_from_args(args) or {},
    }
    with client(args) as http:
        user = call(http, "POST", f"/api/v1/idps/{quote(args.provider)}/users", json=body)
    print(f"{user['name']}: added from {args.provider} (reaches {describe_access(user['access'])})")
    return 0


def cmd_idps(args: argparse.Namespace) -> int:
    with client(args) as http:
        idps = call(http, "GET", "/api/v1/idps")
    if args.json:
        print(json.dumps(idps, indent=2))
        return 0
    if not idps:
        print("no identity-provider modules are configured", file=sys.stderr)
        return 0
    rows: list[tuple[str, ...]] = [("ID", "NAME", "TYPE", "SIGN-IN", "DIRECTORY SEARCH")]
    for p in idps:
        rows.append((p["id"], p["name"], p["type"], p["login"], "yes" if p["can_search"] else "no"))
    print_table(rows)
    return 0


def call(http: httpx.Client, method: str, path: str, **kwargs: Any) -> Any:
    try:
        response = http.request(method, path, **kwargs)
    except httpx.HTTPError as exc:
        raise CliError(f"cannot reach SDL at {http.base_url}: {exc}") from exc
    if response.status_code >= 400:
        detail = _message(_detail(response))
        if response.status_code == 401:
            detail += " (sign in again with 'sdl login')"
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
    p.add_argument("-g", "--group", action="append", help="limit the token to inventory groups")
    p.add_argument("-s", "--system", action="append", help="limit the token to systems")
    p.set_defaults(func=cmd_token_new)
    p = token.add_parser("hash", help="print the SHA-256 of a token read from stdin")
    p.set_defaults(func=cmd_token_hash)

    su = sub.add_parser(
        "superuser", help="create or reset the superuser file (run on the SDL server)"
    ).add_subparsers(dest="superuser_cmd", required=True)
    p = su.add_parser("set", help="create the superuser, or change its name, password or TOTP")
    p.add_argument("-f", "--file", required=True, help="path of identity.superuser_file")
    p.add_argument("--name", help="superuser name (required when creating the file)")
    p.add_argument("--display-name")
    p.add_argument("--keep-password", action="store_true", help="only change the name or TOTP")
    p.add_argument("--password-stdin", action="store_true", help="read the password from stdin")
    p.add_argument("--min-length", type=int, default=12, help=argparse.SUPPRESS)
    p.add_argument("--totp", action="store_true", help="set up (or replace) a TOTP authenticator")
    p.add_argument("--no-totp", action="store_true", help="remove the TOTP authenticator")
    p.set_defaults(func=cmd_superuser_set)
    p = su.add_parser("show", help="show the superuser's name (never the password)")
    p.add_argument("-f", "--file", required=True)
    p.set_defaults(func=cmd_superuser_show)

    p = sub.add_parser("login", help="sign in and keep the session for the next commands")
    p.add_argument("-u", "--user", help="user name (asked when not given)")
    p.add_argument("--provider", help="password identity provider, e.g. an LDAP module id")
    p.add_argument("--sso", metavar="PROVIDER", help="sign in through a single sign-on provider")
    p.add_argument("--code", help="TOTP code (asked when needed)")
    p.add_argument("--password-stdin", action="store_true")
    p.set_defaults(func=cmd_login)
    p = sub.add_parser("logout", help="end the saved session")
    p.set_defaults(func=cmd_logout)
    p = sub.add_parser("whoami", help="show who you are signed in as and what you reach")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_whoami)
    p = sub.add_parser("passwd", help="change your own password")
    p.set_defaults(func=cmd_passwd)
    mfa = sub.add_parser("mfa", help="multi-factor sign-in for your own account").add_subparsers(
        dest="mfa_cmd", required=True
    )
    p = mfa.add_parser("setup", help="set up a TOTP authenticator app")
    p.set_defaults(func=cmd_mfa_setup)

    def access_options(p: argparse.ArgumentParser, *, changes: bool) -> None:
        what = "replace the " if changes else ""
        p.add_argument(
            "-g", "--group", action="append", help=f"{what}inventory groups (repeatable, or a,b)"
        )
        p.add_argument(
            "-s", "--system", action="append", help=f"{what}individual systems (repeatable)"
        )
        p.add_argument(
            "--all-systems",
            dest="all_systems",
            action="store_true",
            default=None,
            help="reach every system",
        )
        if changes:
            p.add_argument("--no-all-systems", dest="all_systems", action="store_false")
            p.add_argument("--add-group", action="append")
            p.add_argument("--remove-group", action="append")
            p.add_argument("--add-system", action="append")
            p.add_argument("--remove-system", action="append")

    roles = "admin, operator, auditor"
    users = sub.add_parser(
        "users", help="manage users, their roles and assignments"
    ).add_subparsers(dest="users_cmd", required=True)
    p = users.add_parser("list", help="list users")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_users_list)
    p = users.add_parser("show", help="show one user")
    p.add_argument("name")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_users_show)
    p = users.add_parser("add", help="add a local user")
    p.add_argument("name")
    p.add_argument("--display-name")
    p.add_argument("--email")
    p.add_argument("-r", "--role", action="append", help=f"role (repeatable): {roles}")
    access_options(p, changes=False)
    p.add_argument("--disabled", action="store_true", help="add the user disabled")
    p.add_argument("--no-password", action="store_true", help="do not set a password yet")
    p.add_argument("--password-stdin", action="store_true")
    p.set_defaults(func=cmd_users_add)
    p = users.add_parser("set", help="change a user's roles, groups, systems or details")
    p.add_argument("name")
    p.add_argument("--display-name")
    p.add_argument("--email")
    p.add_argument("-r", "--role", action="append", help=f"replace the roles: {roles}")
    p.add_argument("--add-role", action="append")
    p.add_argument("--remove-role", action="append")
    access_options(p, changes=True)
    p.add_argument("--enable", dest="enabled", action="store_true", default=None)
    p.add_argument("--disable", dest="enabled", action="store_false")
    p.set_defaults(func=cmd_users_set)
    p = users.add_parser("remove", help="remove users")
    p.add_argument("names", nargs="+")
    p.set_defaults(func=cmd_users_remove)
    p = users.add_parser("password", help="set a local user's password")
    p.add_argument("name")
    p.add_argument("--permanent", action="store_true", help="do not make them change it")
    p.add_argument("--password-stdin", action="store_true")
    p.set_defaults(func=cmd_users_password)
    p = users.add_parser("reset-mfa", help="remove a user's authenticator (lost device)")
    p.add_argument("name")
    p.set_defaults(func=cmd_users_reset_mfa)
    p = users.add_parser("unlock", help="clear a lockout after failed sign-ins")
    p.add_argument("name")
    p.set_defaults(func=cmd_users_unlock)
    p = users.add_parser("search", help="look users up in a directory (LDAP / AD)")
    p.add_argument("provider", help="identity provider id")
    p.add_argument("query", nargs="?", default="")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_users_search)
    p = users.add_parser("import", help="add a directory user before their first sign-in")
    p.add_argument("provider", help="identity provider id")
    p.add_argument("username")
    p.add_argument("-r", "--role", action="append", help=f"extra roles: {roles}")
    access_options(p, changes=False)
    p.set_defaults(func=cmd_users_import)

    p = sub.add_parser("idps", help="list identity providers (LDAP / AD, Entra ID, SAML...)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_idps)

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
    except ValueError as exc:  # superuser file problems, among others
        print(f"sdl: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
