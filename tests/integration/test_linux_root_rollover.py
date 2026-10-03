"""End to end: the first user story against real sshd containers and a dev Vault.

A sysadmin rolls over the root password on a few Linux VMs: SDL connects with
an SSH service account, changes and verifies each password, stores it in
Vault, logs every step, and reports per VM. vm3 is deliberately misconfigured
(no sudo rule) to show a per-VM failure that leaves the VM untouched.

Run with: SDL_INTEGRATION=1 pytest -m integration
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import asyncssh
import httpx
import pytest
import yaml

from sdl.modules.auth_static_token import hash_token

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("SDL_INTEGRATION") != "1", reason="set SDL_INTEGRATION=1 (needs Docker)"
    ),
]

HERE = Path(__file__).parent
COMPOSE = ["docker", "compose", "-f", str(HERE / "docker-compose.yml")]
VAULT_URL = "http://127.0.0.1:18200"
VAULT_TOKEN = "sdl-dev-root"
INITIAL_PASSWORD = "initial-root-password"
VMS = {"vm1": 12221, "vm2": 12222, "vm3": 12223}
TOKEN = "integration-admin-token"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait_for(check: Any, what: str, timeout: float = 120) -> Any:
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


def host_key_line(port: int) -> str:
    key = asyncio.run(
        asyncssh.get_server_host_key("127.0.0.1", port, server_host_key_algs=["ssh-ed25519"])
    )
    return f"[127.0.0.1]:{port} {key.export_public_key().decode().strip()}"


def vault_read(path: str) -> dict[str, Any] | None:
    r = httpx.get(f"{VAULT_URL}/v1/secret/data/sdl/{path}", headers={"X-Vault-Token": VAULT_TOKEN})
    return r.json()["data"] if r.status_code == 200 else None


def root_login_works(port: int, password: str) -> bool:
    async def attempt() -> bool:
        try:
            async with asyncssh.connect(
                "127.0.0.1",
                port,
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


@pytest.fixture(scope="module")
def environment(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Any]]:
    work = tmp_path_factory.mktemp("sdl-it")
    key = asyncssh.generate_private_key("ssh-ed25519")
    key.write_private_key(str(work / "id_ed25519"))
    env = {**os.environ, "SDL_PUBKEY": key.export_public_key().decode().strip()}

    subprocess.run([*COMPOSE, "up", "-d", "--build", "--force-recreate"], check=True, env=env)
    try:
        wait_for(lambda: httpx.get(f"{VAULT_URL}/v1/sys/health").status_code == 200, "vault")
        known_hosts = [wait_for(lambda p=p: host_key_line(p), f"sshd on {p}") for p in VMS.values()]
        (work / "known_hosts").write_text("\n".join(known_hosts) + "\n")

        for name in ("vm1", "vm2"):  # vm3 starts with no stored password
            httpx.post(
                f"{VAULT_URL}/v1/secret/data/sdl/linux/{name}/root",
                headers={"X-Vault-Token": VAULT_TOKEN},
                json={"data": {"password": INITIAL_PASSWORD}},
            ).raise_for_status()

        ssh_common = {
            "username": "sdl-svc",
            "private_key_path": str(work / "id_ed25519"),
            "known_hosts_path": str(work / "known_hosts"),
        }
        config = {
            "modules": {
                "audit": {"type": "audit.jsonl", "config": {"path": str(work / "audit.jsonl")}},
                "auth": {
                    "type": "auth.static_token",
                    "config": {
                        "clients": [
                            {
                                "id": "sysadmin",
                                "token_sha256": hash_token(TOKEN),
                                "roles": ["admin"],
                            }
                        ]
                    },
                },
                "passwords": {"type": "generator.password"},
                "vault": {"type": "secrets.vault", "config": {"url": VAULT_URL}},
                "linux_su": {
                    "type": "target.ssh_linux",
                    "config": {**ssh_common, "verify_method": "su"},
                },
                "linux_login": {
                    "type": "target.ssh_linux",
                    "config": {**ssh_common, "verify_method": "ssh_login"},
                },
            },
            "targets": [
                {
                    "name": name,
                    "host": "127.0.0.1",
                    "port": port,
                    "module": "linux_login" if name == "vm2" else "linux_su",
                    "secret_path": f"linux/{name}/root",
                    "groups": ["lab"],
                }
                for name, port in VMS.items()
            ],
        }
        (work / "sdl.yaml").write_text(yaml.safe_dump(config))

        port = free_port()
        server_env = {**os.environ, "VAULT_TOKEN": VAULT_TOKEN}
        server = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "sdl.cli.main",
                "serve",
                "-c",
                str(work / "sdl.yaml"),
                "--port",
                str(port),
            ],
            env=server_env,
            stdout=open(work / "server.log", "w"),
            stderr=subprocess.STDOUT,
        )
        url = f"http://127.0.0.1:{port}"
        try:
            wait_for(lambda: httpx.get(f"{url}/health").status_code == 200, "sdl api", timeout=30)
            yield {"url": url, "work": work}
        finally:
            server.terminate()
            server.wait(timeout=30)
            print((work / "server.log").read_text())
    finally:
        if os.environ.get("SDL_IT_KEEP") != "1":
            subprocess.run([*COMPOSE, "down", "-v", "--remove-orphans"], check=False, env=env)


def sdl(environment: dict[str, Any], *args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "SDL_URL": environment["url"], "SDL_TOKEN": TOKEN}
    return subprocess.run(
        [sys.executable, "-m", "sdl.cli.main", *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )


def test_dry_run_reports_misconfigured_vm(environment: dict[str, Any]) -> None:
    result = sdl(environment, "rollover", "run", "--all", "--dry-run", "-r", "pre-check", "--json")
    assert result.returncode == 1, result.stderr
    run = json.loads(result.stdout)
    status = {r["target"]: r for r in run["results"]}
    assert status["vm1"]["status"] == "checked"
    assert status["vm2"]["status"] == "checked"
    assert status["vm3"]["status"] == "failed"
    assert "sudo" in status["vm3"]["message"]
    assert root_login_works(VMS["vm1"], INITIAL_PASSWORD)


def test_root_password_rollover(environment: dict[str, Any]) -> None:
    result = sdl(environment, "rollover", "run", "--group", "lab", "-r", "rotate root now", "-v")
    print(result.stdout)
    assert result.returncode == 1  # vm3 fails, so the run is partial
    assert "PARTIAL" in result.stdout

    for name in ("vm1", "vm2"):
        stored = vault_read(f"linux/{name}/root")
        assert stored is not None
        new_password = stored["data"]["password"]
        assert new_password != INITIAL_PASSWORD
        assert stored["data"]["state"] == "active"
        assert stored["metadata"]["version"] == 2
        assert root_login_works(VMS[name], new_password), name
        assert not root_login_works(VMS[name], INITIAL_PASSWORD), name
        assert vault_read(f"linux/{name}/root/__sdl_pending") is None

    # vm3 was never touched.
    assert root_login_works(VMS["vm3"], INITIAL_PASSWORD)
    assert vault_read("linux/vm3/root/__sdl_pending") is None


def test_second_rollover_on_one_vm(environment: dict[str, Any]) -> None:
    before = vault_read("linux/vm1/root")
    assert before is not None
    result = sdl(environment, "rollover", "run", "-t", "vm1", "-r", "again", "--json")
    assert result.returncode == 0, result.stdout + result.stderr
    after = vault_read("linux/vm1/root")
    assert after is not None
    assert after["metadata"]["version"] == 3
    assert root_login_works(VMS["vm1"], after["data"]["password"])
    assert not root_login_works(VMS["vm1"], before["data"]["password"])


def test_audit_log_is_complete_intact_and_secret_free(environment: dict[str, Any]) -> None:
    verify = sdl(environment, "audit", "--verify")
    assert verify.returncode == 0, verify.stdout
    log_text = (environment["work"] / "audit.jsonl").read_text()
    assert INITIAL_PASSWORD not in log_text
    for name in ("vm1", "vm2"):
        stored = vault_read(f"linux/{name}/root")
        assert stored is not None
        assert stored["data"]["password"] not in log_text

    runs = json.loads(sdl(environment, "rollover", "list", "--json").stdout)
    rollover = next(r for r in runs if r["reason"] == "rotate root now")
    events = json.loads(sdl(environment, "audit", "--run", rollover["id"], "--json").stdout)
    vm1_steps = [e["action"].rsplit(".", 1)[-1] for e in events if e["target"] == "vm1"]
    for step in (
        "connect",
        "preflight",
        "read_previous",
        "generate",
        "escrow",
        "change",
        "verify",
        "store",
        "cleanup",
    ):
        assert step in vm1_steps


@pytest.mark.parametrize("method", ["su", "ssh_login"])
def test_verification_rejects_wrong_password(environment: dict[str, Any], method: str) -> None:
    from pydantic import SecretStr

    from sdl.core.audit import AuditRecorder
    from sdl.core.models import TargetSpec
    from sdl.core.module import ModuleContext
    from sdl.modules.target_ssh_linux import SshLinuxConfig, SshLinuxTargetModule

    work = environment["work"]
    module = SshLinuxTargetModule(
        SshLinuxConfig(
            username="sdl-svc",
            private_key_path=work / "id_ed25519",
            known_hosts_path=work / "known_hosts",
            verify_method=method,
        ),
        ModuleContext("probe", AuditRecorder()),
    )
    target = TargetSpec(
        name="vm3", host="127.0.0.1", port=VMS["vm3"], module="probe", secret_path="x"
    )

    async def check() -> tuple[bool, bool]:
        async with await module.open_session(target) as session:
            right = await session.verify_credential(SecretStr(INITIAL_PASSWORD))
            wrong = await session.verify_credential(SecretStr("definitely-not-it"))
            return right, wrong

    assert asyncio.run(check()) == (True, False)
