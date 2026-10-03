"""The SDL lab's helper, run inside the lab's SDL container.

  serve              prepare the lab (SSH key, known_hosts, Vault, sdl.yaml),
                     run `sdl serve`, and add the lab systems to SDL's inventory
  ready              exit 0 once SDL answers and the lab systems are in place
  password SYSTEM    print the root password Vault holds for a lab system
  root-login SYSTEM  try root logins on the system's VM with Vault's password
                     and with the lab's initial one
  smoke              a quick automated pass over the lab (used by CI)

Normally reached through ./lab/lab.sh on the host.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import asyncssh
import httpx
import yaml

from sdl.modules.auth_static_token import hash_token

STATE = Path("/lab/state")
KEYS = Path("/lab/keys")
KEY = KEYS / "id_ed25519"
CONFIG = STATE / "sdl.yaml"
SEEDED = STATE / "inventory-seeded"
VAULT = os.environ.get("VAULT_ADDR", "http://vault:8200")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "sdl-lab-root")
SDL = "http://127.0.0.1:8800"
INITIAL_PASSWORD = "lab-initial-password"
SERVICE_ACCOUNT_PATH = "svc/sdl-svc"

TOKENS = {"admin": "admin-token", "operator": "operator-token", "auditor": "auditor-token"}

# name: (VM, where SDL learns about it, groups, description)
SYSTEMS: dict[str, tuple[str, str, list[str], str]] = {
    "web1": ("vm1", "inventory", ["web", "lab"], "Web server; healthy"),
    "web2": ("vm2", "inventory", ["web", "lab"], "Web server on another distribution"),
    "db1": ("vm3", "inventory", ["db", "lab"], "Database; service account has no sudo rule"),
    "app1": ("vm4", "sdl.yaml", ["app", "lab"], "App server listed in sdl.yaml"),
}


def secret_path(system: str) -> str:
    return f"linux/{system}/root"


def wait_for(check: Callable[[], Any], what: str, timeout: float = 180) -> Any:
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            result = check()
            if result:
                return result
        except Exception as exc:
            last = exc
        time.sleep(1)
    raise TimeoutError(f"{what} not ready: {last}")


# --- Vault ------------------------------------------------------------------


def vault_read(path: str) -> dict[str, Any] | None:
    r = httpx.get(f"{VAULT}/v1/secret/data/sdl/{path}", headers={"X-Vault-Token": VAULT_TOKEN})
    if r.status_code == 404:
        return None
    r.raise_for_status()
    data: dict[str, Any] = r.json()["data"]
    return data


def vault_write(path: str, data: dict[str, Any]) -> None:
    httpx.post(
        f"{VAULT}/v1/secret/data/sdl/{path}",
        headers={"X-Vault-Token": VAULT_TOKEN},
        json={"data": data},
    ).raise_for_status()


def vault_ready() -> bool:
    r = httpx.get(f"{VAULT}/v1/auth/token/lookup-self", headers={"X-Vault-Token": VAULT_TOKEN})
    return r.status_code == 200


# --- SSH --------------------------------------------------------------------


def host_key_line(host: str) -> str:
    key = asyncio.run(asyncssh.get_server_host_key(host, 22, server_host_key_algs=["ssh-ed25519"]))
    return f"{host} {key.export_public_key().decode().strip()}"


def root_login_works(host: str, password: str) -> bool:
    async def attempt() -> bool:
        try:
            async with asyncssh.connect(
                host,
                22,
                username="root",
                password=password,
                known_hosts=None,
                client_keys=None,
                agent_path=None,
                preferred_auth="password",
            ) as conn:
                return (await conn.run("id -u", check=True)).stdout.strip() == "0"
        except asyncssh.PermissionDenied:
            return False

    return asyncio.run(attempt())


# --- serve ------------------------------------------------------------------


def config() -> dict[str, Any]:
    return {
        "modules": {
            "audit": {"type": "audit.jsonl", "config": {"path": str(STATE / "audit.jsonl")}},
            "auth": {
                "type": "auth.static_token",
                "config": {
                    "clients": [
                        {
                            "id": role,
                            "display_name": f"Lab {role}",
                            "token_sha256": hash_token(token),
                            "roles": [role],
                        }
                        for role, token in TOKENS.items()
                    ]
                },
            },
            "inventory": {
                "type": "inventory.store",
                "config": {"path": str(STATE / "inventory.json")},
            },
            "passwords": {"type": "generator.password", "config": {"length": 24}},
            "vault": {"type": "secrets.vault", "config": {"url": VAULT}},
            "linux": {
                "type": "target.ssh_linux",
                "config": {
                    "username": "sdl-svc",
                    "private_key_path": str(KEY),
                    "known_hosts_path": str(STATE / "known_hosts"),
                    "verify_method": "su",
                },
            },
            "syslog": {"type": "forwarder.syslog", "config": {"host": "sink", "protocol": "tcp"}},
            "graylog": {"type": "forwarder.gelf", "config": {"url": "http://sink:12201/gelf"}},
            "splunk": {
                "type": "forwarder.splunk_hec",
                "config": {"url": "http://sink:8088", "exclude_actions": ["api.request"]},
            },
        },
        "targets": [
            {
                "name": name,
                "hostname": vm,
                "fqdn": f"{name}.lab.example.com",
                "addresses": [socket.gethostbyname(vm)],
                "host": vm,
                "module": "linux",
                "secret_path": secret_path(name),
                "groups": groups,
                "description": description,
            }
            for name, (vm, source, groups, description) in SYSTEMS.items()
            if source == "sdl.yaml"
        ],
        "rollover": {"max_parallel": 5},
    }


def prepare() -> None:
    STATE.mkdir(parents=True, exist_ok=True)
    KEYS.mkdir(parents=True, exist_ok=True)
    if not KEY.exists():
        key = asyncssh.generate_private_key("ssh-ed25519", comment="sdl-lab")
        key.write_private_key(str(KEY))
        KEY.chmod(0o600)
        (KEYS / "id_ed25519.pub.tmp").write_bytes(key.export_public_key())
        (KEYS / "id_ed25519.pub.tmp").rename(KEYS / "id_ed25519.pub")
        print("lab: created the service account's SSH key", flush=True)

    vms = sorted({vm for vm, *_ in SYSTEMS.values()})
    lines = [wait_for(lambda vm=vm: host_key_line(vm), f"sshd on {vm}") for vm in vms]
    (STATE / "known_hosts").write_text("\n".join(lines) + "\n")

    wait_for(vault_ready, "vault")
    pem = KEY.read_text()
    current = vault_read(SERVICE_ACCOUNT_PATH)
    if current is None or current["data"].get("password") != pem:
        vault_write(SERVICE_ACCOUNT_PATH, {"password": pem})
    for name in SYSTEMS:
        if vault_read(secret_path(name)) is None:
            vault_write(secret_path(name), {"password": INITIAL_PASSWORD})

    CONFIG.write_text(yaml.safe_dump(config(), sort_keys=False))


def cli(*args: str, role: str = "admin") -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "SDL_URL": SDL, "SDL_TOKEN": TOKENS[role]}
    return subprocess.run(["sdl", *args], env=env, capture_output=True, text=True, timeout=300)


def seed_inventory() -> None:
    listed = cli("systems", "list", "--json")
    if listed.returncode != 0:
        raise RuntimeError(listed.stderr)
    present = {s["name"] for s in json.loads(listed.stdout)}
    for name, (vm, source, groups, description) in SYSTEMS.items():
        if source != "inventory" or name in present:
            continue
        added = cli(
            "systems", "add", name,
            "--inventory", "inventory",
            "--hostname", vm,
            "--fqdn", f"{name}.lab.example.com",
            "--ip", socket.gethostbyname(vm),
            "--host", vm,
            "--secret-path", secret_path(name),
            "--service-account", "sdl-svc",
            "--service-account-path", SERVICE_ACCOUNT_PATH,
            *(arg for g in groups for arg in ("-g", g)),
            "--description", description,
        )  # fmt: skip
        if added.returncode != 0:
            raise RuntimeError(f"adding {name}: {added.stdout}{added.stderr}")
    SEEDED.touch()


def serve() -> int:
    SEEDED.unlink(missing_ok=True)
    prepare()
    server = subprocess.Popen(
        ["sdl", "serve", "-c", str(CONFIG), "--host", "0.0.0.0", "--port", "8800"]
    )
    signal.signal(signal.SIGTERM, lambda *_: server.terminate())
    signal.signal(signal.SIGINT, lambda *_: server.terminate())
    try:
        wait_for(lambda: httpx.get(f"{SDL}/health").status_code == 200, "sdl", timeout=60)
        seed_inventory()
        print("lab: ready on http://127.0.0.1:8800/ui/", flush=True)
    except Exception as exc:
        print(f"lab: setup failed: {exc}", file=sys.stderr, flush=True)
    return server.wait()


def ready() -> int:
    try:
        ok = httpx.get(f"{SDL}/health", timeout=2).status_code == 200 and SEEDED.exists()
    except httpx.HTTPError:
        ok = False
    return 0 if ok else 1


# --- checks -----------------------------------------------------------------


def stored_password(system: str) -> tuple[str, int]:
    if system not in SYSTEMS:
        raise SystemExit(f"unknown lab system {system!r}; pick one of {', '.join(SYSTEMS)}")
    stored = vault_read(secret_path(system))
    if stored is None:
        raise SystemExit(f"Vault holds nothing at {secret_path(system)}")
    return stored["data"]["password"], stored["metadata"]["version"]


def password(system: str) -> int:
    value, version = stored_password(system)
    print(f"{value}    (secret/sdl/{secret_path(system)}, version {version})")
    return 0


def root_login(system: str) -> int:
    value, version = stored_password(system)
    vm = SYSTEMS[system][0]
    with_vault = root_login_works(vm, value)
    with_initial = value != INITIAL_PASSWORD and root_login_works(vm, INITIAL_PASSWORD)
    print(
        f"{system} ({vm}): root login with Vault's password (version {version}): "
        f"{'WORKS' if with_vault else 'FAILS'}"
    )
    if value != INITIAL_PASSWORD:
        print(
            f"{system} ({vm}): root login with the lab's initial password: "
            f"{'WORKS' if with_initial else 'fails (as it should after a rollover)'}"
        )
    return 0 if with_vault and not with_initial else 1


def smoke() -> int:
    failures: list[str] = []

    def check(what: str, ok: bool, detail: str = "") -> None:
        print(f"{'PASS' if ok else 'FAIL'}  {what}" + (f": {detail}" if detail and not ok else ""))
        if not ok:
            failures.append(what)

    listed = json.loads(cli("systems", "list", "--json").stdout)
    check("all four lab systems are listed", sorted(s["name"] for s in listed) == sorted(SYSTEMS))

    before = stored_password("web1")
    run = cli("rollover", "run", "-t", "web1", "-t", "db1", "-r", "lab smoke test", "--json")
    results = {r["target"]: r for r in json.loads(run.stdout)["results"]}
    check("web1 rolls over", results["web1"]["status"] == "succeeded", str(results["web1"]))
    check(
        "db1 fails on its missing sudo rule",
        results["db1"]["status"] == "failed" and "sudo" in results["db1"]["message"],
        str(results["db1"]),
    )
    after = stored_password("web1")
    check("Vault has a new web1 version", after[1] == before[1] + 1, f"{before[1]} -> {after[1]}")
    check("web1 root login works with the new password", root_login_works("vm1", after[0]))
    check("web1 root login fails with the old one", not root_login_works("vm1", before[0]))
    check("db1 still has its old password", root_login_works("vm3", INITIAL_PASSWORD))

    denied = cli("rollover", "run", "-t", "web2", "-r", "not allowed", role="auditor")
    check(
        "an auditor cannot roll over",
        denied.returncode != 0 and "403" in denied.stderr,
        denied.stdout + denied.stderr,
    )
    denied = cli("systems", "remove", "web2", "--inventory", "inventory", role="operator")
    check(
        "an operator cannot change the inventory",
        denied.returncode != 0,
        denied.stdout + denied.stderr,
    )

    verify = cli("audit", "--verify")
    check("the audit log's hash chain verifies", verify.returncode == 0, verify.stdout)

    def forwarded() -> bool:
        counts = httpx.get("http://sink:8900/events").json()["counts"]
        return all(counts[k] > 0 for k in ("syslog", "graylog", "splunk"))

    try:
        wait_for(forwarded, "forwarded events", timeout=30)
        check("syslog, Graylog and Splunk each received events", True)
    except TimeoutError as exc:
        check("syslog, Graylog and Splunk each received events", False, str(exc))

    print(f"\n{'all checks passed' if not failures else f'{len(failures)} check(s) failed'}")
    return 1 if failures else 0


def main() -> int:
    args = sys.argv[1:]
    if args == ["serve"]:
        return serve()
    if args == ["ready"]:
        return ready()
    if args == ["smoke"]:
        return smoke()
    if len(args) == 2 and args[0] == "password":
        return password(args[1])
    if len(args) == 2 and args[0] == "root-login":
        return root_login(args[1])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
