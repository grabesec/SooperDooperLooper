from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import Field, SecretStr

from sdl.core.models import SecretRecord, ServiceCredential, TargetSpec
from sdl.core.module import ModuleConfig, ModuleError, SecretsModule, TargetModule, TargetSession
from sdl.core.orchestrator import Orchestrator
from sdl.core.registry import ModuleRegistry
from sdl.core.settings import Settings
from sdl.modules.auth_static_token import hash_token

ADMIN_TOKEN = "admin-token-for-tests"
OPERATOR_TOKEN = "operator-token-for-tests"
AUDITOR_TOKEN = "auditor-token-for-tests"


class FakeHosts:
    """Shared state standing in for real machines: host name -> current password."""

    def __init__(self) -> None:
        self.passwords: dict[str, str] = {}
        self.change_calls: dict[str, int] = {}
        self.logins: list[tuple[str, str, str]] = []


HOSTS = FakeHosts()


class FakeTargetSession(TargetSession):
    def __init__(self, target: TargetSpec) -> None:
        self.target = target
        self.options = target.options

    async def preflight(self) -> list[str]:
        if self.options.get("fail_preflight"):
            raise ModuleError("sudo is not allowed")
        return ["fake preflight ok"]

    async def set_credential(self, value: SecretStr) -> None:
        host = self.target.host
        HOSTS.change_calls[host] = HOSTS.change_calls.get(host, 0) + 1
        if self.options.get("fail_change"):
            raise ModuleError("chpasswd exited with 1")
        HOSTS.passwords[host] = value.get_secret_value()
        if self.options.get("error_after_change"):
            raise ModuleError("connection dropped")

    async def verify_credential(self, value: SecretStr) -> bool:
        if self.options.get("reject_all"):
            return False
        current = HOSTS.passwords.get(self.target.host)
        if self.options.get("reject_new") and HOSTS.change_calls.get(self.target.host, 0) == 1:
            return False
        return current == value.get_secret_value()


class FakeTargetModule(TargetModule):
    async def open_session(
        self, target: TargetSpec, credential: ServiceCredential | None = None
    ) -> TargetSession:
        if credential is not None:
            HOSTS.logins.append((target.host, credential.username, credential.credential_type))
            expected = target.options.get("service_secret")
            if expected is not None and credential.secret.get_secret_value() != expected:
                raise ModuleError(f"{target.host} rejected the service account")
        if target.options.get("fail_connect"):
            raise ModuleError(f"cannot connect to {target.host}:22: Connection refused")
        return FakeTargetSession(target)


class FakeSecretsConfig(ModuleConfig):
    fail_read: bool = False
    fail_write_paths: list[str] = Field(default_factory=list)


class FakeSecretsModule(SecretsModule):
    Config = FakeSecretsConfig
    config: FakeSecretsConfig

    def __init__(self, config: Any, context: Any) -> None:
        super().__init__(config, context)
        self.store: dict[str, list[SecretRecord]] = {}

    async def read(self, path: str) -> SecretRecord | None:
        if self.config.fail_read:
            raise ModuleError("vault is sealed")
        versions = self.store.get(path)
        return versions[-1] if versions else None

    async def write(self, path: str, record: SecretRecord) -> str | None:
        if any(path.endswith(p) for p in self.config.fail_write_paths):
            raise ModuleError("permission denied")
        versions = self.store.setdefault(path, [])
        versions.append(record.model_copy(update={"version": str(len(versions) + 1)}))
        return str(len(versions))

    async def delete(self, path: str) -> None:
        self.store.pop(path, None)


def make_registry() -> ModuleRegistry:
    registry = ModuleRegistry.from_entry_points()
    registry.register("target.fake", FakeTargetModule)
    registry.register("secrets.fake", FakeSecretsModule)
    return registry


def make_settings(
    tmp_path: Path,
    targets: list[dict[str, Any]] | None = None,
    secrets_config: dict[str, Any] | None = None,
    extra_modules: dict[str, Any] | None = None,
) -> Settings:
    if targets is None:
        targets = [
            {"name": "vm1", "host": "vm1.test", "groups": ["web"]},
            {"name": "vm2", "host": "vm2.test", "groups": ["web"]},
            {"name": "vm3", "host": "vm3.test", "groups": ["db"]},
        ]
    return Settings.model_validate(
        {
            "modules": {
                "audit": {"type": "audit.jsonl", "config": {"path": str(tmp_path / "audit.jsonl")}},
                "auth": {
                    "type": "auth.static_token",
                    "config": {
                        "clients": [
                            {
                                "id": "alice",
                                "token_sha256": hash_token(ADMIN_TOKEN),
                                "roles": ["admin"],
                            },
                            {
                                "id": "bob",
                                "token_sha256": hash_token(OPERATOR_TOKEN),
                                "roles": ["operator"],
                            },
                            {
                                "id": "carol",
                                "token_sha256": hash_token(AUDITOR_TOKEN),
                                "roles": ["auditor"],
                            },
                        ]
                    },
                },
                "passwords": {"type": "generator.password", "config": {"length": 24}},
                "vault": {"type": "secrets.fake", "config": secrets_config or {}},
                "linux": {"type": "target.fake"},
                **(extra_modules or {}),
            },
            "targets": [
                {"module": "linux", "secret_path": f"linux/{t['name']}/root", **t} for t in targets
            ],
        }
    )


@pytest.fixture(autouse=True)
def _reset_hosts() -> None:
    HOSTS.passwords.clear()
    HOSTS.change_calls.clear()
    HOSTS.logins.clear()


@pytest.fixture
def hosts() -> FakeHosts:
    return HOSTS


@pytest.fixture
def orchestrator_factory(tmp_path: Path) -> Any:
    created: list[Orchestrator] = []

    def factory(**kwargs: Any) -> Orchestrator:
        orchestrator = Orchestrator(make_settings(tmp_path, **kwargs), registry=make_registry())
        created.append(orchestrator)
        return orchestrator

    return factory
