from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from sdl.core.audit import AuditRecorder, AuditUnavailableError, redact
from sdl.core.models import Outcome, TargetSpec
from sdl.core.module import ModuleContext
from sdl.core.orchestrator import ConfigError, Orchestrator
from sdl.core.registry import ModuleRegistry, UnknownModuleError
from sdl.core.settings import Settings
from sdl.modules.audit_jsonl import JsonlAuditConfig, JsonlAuditModule
from sdl.modules.generator_password import AMBIGUOUS, PasswordGeneratorModule, PasswordPolicy
from tests.conftest import make_registry, make_settings

TARGET = TargetSpec(name="vm", host="vm", module="linux", secret_path="x")


def generator(**policy: Any) -> PasswordGeneratorModule:
    return PasswordGeneratorModule(PasswordPolicy(**policy), ModuleContext("gen", AuditRecorder()))


def test_password_generator_follows_policy() -> None:
    gen = generator(length=40)
    seen = set()
    for _ in range(200):
        password = gen.generate(TARGET).get_secret_value()
        assert len(password) == 40
        assert any(c.islower() for c in password)
        assert any(c.isupper() for c in password)
        assert any(c.isdigit() for c in password)
        assert any(c in PasswordPolicy().symbols for c in password)
        assert not set(password) & AMBIGUOUS
        assert not set(password) & set(":'\"\\ \n")
        seen.add(password)
    assert len(seen) == 200


def test_password_generator_per_target_length() -> None:
    target = TARGET.model_copy(update={"options": {"password_length": 64}})
    assert len(generator().generate(target).get_secret_value()) == 64


def test_password_policy_rejects_unsafe_settings() -> None:
    with pytest.raises(ValidationError):
        PasswordPolicy(symbols="ab:")
    with pytest.raises(ValidationError):
        PasswordPolicy(length=8)
    with pytest.raises(ValidationError):
        PasswordPolicy(lowercase=False, uppercase=False, digits=False, symbols="")


def test_redact_hides_secret_values() -> None:
    data = {
        "password": "hunter2",
        "api_token": "abc",
        "secret_path": "linux/vm/root",
        "secret_version": "3",
        "nested": {"value": SecretStr("s3cret"), "private_key": "xyz", "private_key_path": "/k"},
        "list": [SecretStr("a"), "b"],
        "host": "vm1",
    }
    assert redact(data) == {
        "password": "[redacted]",
        "api_token": "[redacted]",
        "secret_path": "linux/vm/root",
        "secret_version": "3",
        "nested": {"value": "[redacted]", "private_key": "[redacted]", "private_key_path": "/k"},
        "list": ["[redacted]", "b"],
        "host": "vm1",
    }


async def test_jsonl_audit_chain_detects_tampering(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    recorder = AuditRecorder()
    module = JsonlAuditModule(
        JsonlAuditConfig(path=path, fsync=False), ModuleContext("audit", recorder)
    )
    recorder.attach([module])
    await module.start()
    for i in range(5):
        await recorder.record("test.event", Outcome.INFO, message=f"event {i}", password="nope")
    assert await module.verify() == (True, "5 events, chain intact")
    assert "nope" not in path.read_text()

    # A restarted module continues the same chain.
    module2 = JsonlAuditModule(
        JsonlAuditConfig(path=path, fsync=False), ModuleContext("audit", recorder)
    )
    await module2.start()
    recorder.attach([module2])
    await recorder.record("test.event", Outcome.INFO, message="after restart")
    assert (await module2.verify())[0]
    assert len(await module2.query(limit=3)) == 3

    lines = path.read_text().splitlines()
    edited = json.loads(lines[2])
    edited["message"] = "something else"
    path.write_text("\n".join([*lines[:2], json.dumps(edited), *lines[3:]]) + "\n")
    ok, detail = await module2.verify()
    assert not ok and "line 3" in detail

    path.write_text("\n".join([*lines[:2], *lines[3:]]) + "\n")
    ok, detail = await module2.verify()
    assert not ok and "chain broken at line 3" in detail


async def test_recorder_fails_closed_without_audit_modules() -> None:
    with pytest.raises(AuditUnavailableError):
        await AuditRecorder().record("x", Outcome.INFO)


def test_registry_finds_builtin_modules() -> None:
    available = ModuleRegistry.from_entry_points().available()
    assert {
        "audit.jsonl",
        "auth.static_token",
        "generator.password",
        "secrets.vault",
        "target.ssh_linux",
    } <= set(available)
    with pytest.raises(UnknownModuleError):
        ModuleRegistry.from_entry_points().resolve("target.nope")
    assert ModuleRegistry().resolve("sdl.modules.audit_jsonl:JsonlAuditModule") is JsonlAuditModule


def test_config_errors_are_caught_at_load(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    settings.modules["linux"].config = {"unexpected": True}
    with pytest.raises(ConfigError, match="linux"):
        Orchestrator(settings, registry=make_registry()).load()

    settings = make_settings(tmp_path)
    settings.targets[0].module = "vault"
    with pytest.raises(ConfigError, match="vm1"):
        Orchestrator(settings, registry=make_registry()).load()

    settings = make_settings(tmp_path)
    del settings.modules["audit"]
    with pytest.raises(ConfigError, match="audit"):
        Orchestrator(settings, registry=make_registry()).load()

    with pytest.raises(ValidationError, match="duplicate"):
        make_settings(tmp_path, targets=[{"name": "a", "host": "a"}, {"name": "a", "host": "b"}])


def test_example_config_is_valid() -> None:
    example = Path(__file__).parents[2] / "examples" / "sdl.yaml"
    Orchestrator(Settings.load(example)).load()
