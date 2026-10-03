from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr

from sdl.core.models import (
    Actor,
    ActorType,
    AuditQuery,
    RolloverRequest,
    RunStatus,
    SecretRecord,
    TargetStatus,
)
from sdl.core.orchestrator import Orchestrator, RequestError
from tests.conftest import FakeHosts, FakeSecretsModule

ALICE = Actor(type=ActorType.USER, id="alice", roles=["admin"])


async def run_rollover(orchestrator: Orchestrator, **request: Any) -> Any:
    request.setdefault("all", True)
    request.setdefault("reason", "test rotation")
    run = await orchestrator.start_rollover(RolloverRequest(**request), ALICE)
    return await orchestrator.wait(run.id, timeout=10)


def vault(orchestrator: Orchestrator) -> FakeSecretsModule:
    module = orchestrator.modules["vault"]
    assert isinstance(module, FakeSecretsModule)
    return module


async def seed(orchestrator: Orchestrator, hosts: FakeHosts, name: str, password: str) -> None:
    hosts.passwords[f"{name}.test"] = password
    await vault(orchestrator).write(f"linux/{name}/root", SecretRecord(value=SecretStr(password)))


async def test_successful_rollover_sets_verifies_and_stores(
    orchestrator_factory: Any, hosts: FakeHosts
) -> None:
    orchestrator = orchestrator_factory()
    await orchestrator.start()
    for name in ("vm1", "vm2", "vm3"):
        await seed(orchestrator, hosts, name, f"old-{name}")

    run = await run_rollover(orchestrator)

    assert run.status == RunStatus.SUCCEEDED
    for result in run.results:
        assert result.status == TargetStatus.SUCCEEDED, result.message
        stored = vault(orchestrator).store[result.secret_path][-1]
        assert stored.value.get_secret_value() == hosts.passwords[result.host]
        assert stored.value.get_secret_value() != f"old-{result.target}"
        assert stored.attributes["state"] == "active"
        assert result.secret_version == "2"
        assert [s.name for s in result.steps] == [
            "start",
            "connect",
            "preflight",
            "read_previous",
            "generate",
            "escrow",
            "change",
            "change",
            "verify",
            "store",
            "cleanup",
        ]
    # The staging copies are gone.
    assert not [p for p in vault(orchestrator).store if p.endswith("__sdl_pending")]
    await orchestrator.stop()


async def test_first_rollover_without_previous_secret(
    orchestrator_factory: Any, hosts: FakeHosts
) -> None:
    orchestrator = orchestrator_factory(targets=[{"name": "vm1", "host": "vm1.test"}])
    await orchestrator.start()
    run = await run_rollover(orchestrator)
    assert run.results[0].status == TargetStatus.SUCCEEDED
    assert (
        vault(orchestrator).store["linux/vm1/root"][-1].value.get_secret_value()
        == hosts.passwords["vm1.test"]
    )
    await orchestrator.stop()


async def test_selects_targets_by_group_and_name(orchestrator_factory: Any) -> None:
    orchestrator = orchestrator_factory()
    await orchestrator.start()
    run = await run_rollover(orchestrator, all=False, groups=["db"], targets=["vm1"])
    assert sorted(r.target for r in run.results) == ["vm1", "vm3"]
    with pytest.raises(RequestError, match="unknown target"):
        await run_rollover(orchestrator, all=False, targets=["nope"])
    with pytest.raises(RequestError, match="no targets selected"):
        await run_rollover(orchestrator, all=False)
    await orchestrator.stop()


async def test_dry_run_changes_nothing(orchestrator_factory: Any, hosts: FakeHosts) -> None:
    orchestrator = orchestrator_factory()
    await orchestrator.start()
    await seed(orchestrator, hosts, "vm1", "old")
    run = await run_rollover(orchestrator, dry_run=True)
    assert run.status == RunStatus.SUCCEEDED
    assert {r.status for r in run.results} == {TargetStatus.CHECKED}
    assert hosts.passwords == {"vm1.test": "old"}
    assert hosts.change_calls == {}
    await orchestrator.stop()


async def test_connect_failure_is_reported_per_target(
    orchestrator_factory: Any, hosts: FakeHosts
) -> None:
    orchestrator = orchestrator_factory(
        targets=[
            {"name": "vm1", "host": "vm1.test"},
            {"name": "vm2", "host": "vm2.test", "options": {"fail_connect": True}},
        ]
    )
    await orchestrator.start()
    run = await run_rollover(orchestrator)
    assert run.status == RunStatus.PARTIAL
    by_name = {r.target: r for r in run.results}
    assert by_name["vm1"].status == TargetStatus.SUCCEEDED
    assert by_name["vm2"].status == TargetStatus.FAILED
    assert "Connection refused" in (by_name["vm2"].message or "")
    await orchestrator.stop()


async def test_preflight_failure_changes_nothing(
    orchestrator_factory: Any, hosts: FakeHosts
) -> None:
    orchestrator = orchestrator_factory(
        targets=[{"name": "vm1", "host": "vm1.test", "options": {"fail_preflight": True}}]
    )
    await orchestrator.start()
    run = await run_rollover(orchestrator)
    assert run.results[0].status == TargetStatus.FAILED
    assert hosts.change_calls == {}
    await orchestrator.stop()


async def test_unreadable_secrets_store_aborts_before_change(
    orchestrator_factory: Any, hosts: FakeHosts
) -> None:
    orchestrator = orchestrator_factory(secrets_config={"fail_read": True})
    await orchestrator.start()
    run = await run_rollover(orchestrator)
    assert run.status == RunStatus.FAILED
    assert hosts.change_calls == {}
    await orchestrator.stop()


async def test_escrow_failure_aborts_before_change(
    orchestrator_factory: Any, hosts: FakeHosts
) -> None:
    orchestrator = orchestrator_factory(secrets_config={"fail_write_paths": ["__sdl_pending"]})
    await orchestrator.start()
    run = await run_rollover(orchestrator)
    assert {r.status for r in run.results} == {TargetStatus.FAILED}
    assert hosts.change_calls == {}
    await orchestrator.stop()


async def test_failed_change_keeps_previous_password(
    orchestrator_factory: Any, hosts: FakeHosts
) -> None:
    orchestrator = orchestrator_factory(
        targets=[{"name": "vm1", "host": "vm1.test", "options": {"fail_change": True}}]
    )
    await orchestrator.start()
    await seed(orchestrator, hosts, "vm1", "old")
    run = await run_rollover(orchestrator)
    result = run.results[0]
    assert result.status == TargetStatus.FAILED
    assert "previous one is still in place" in (result.message or "")
    assert hosts.passwords["vm1.test"] == "old"
    assert vault(orchestrator).store["linux/vm1/root"][-1].value.get_secret_value() == "old"
    assert "linux/vm1/root/__sdl_pending" not in vault(orchestrator).store
    await orchestrator.stop()


async def test_change_that_errors_but_applied_still_completes(
    orchestrator_factory: Any, hosts: FakeHosts
) -> None:
    orchestrator = orchestrator_factory(
        targets=[{"name": "vm1", "host": "vm1.test", "options": {"error_after_change": True}}]
    )
    await orchestrator.start()
    await seed(orchestrator, hosts, "vm1", "old")
    run = await run_rollover(orchestrator)
    assert run.results[0].status == TargetStatus.SUCCEEDED
    assert (
        vault(orchestrator).store["linux/vm1/root"][-1].value.get_secret_value()
        == hosts.passwords["vm1.test"]
    )
    await orchestrator.stop()


async def test_rejected_new_password_rolls_back(
    orchestrator_factory: Any, hosts: FakeHosts
) -> None:
    orchestrator = orchestrator_factory(
        targets=[{"name": "vm1", "host": "vm1.test", "options": {"reject_new": True}}]
    )
    await orchestrator.start()
    await seed(orchestrator, hosts, "vm1", "old")
    run = await run_rollover(orchestrator)
    result = run.results[0]
    assert result.status == TargetStatus.ROLLED_BACK
    assert hosts.passwords["vm1.test"] == "old"
    assert vault(orchestrator).store["linux/vm1/root"][-1].value.get_secret_value() == "old"
    assert "linux/vm1/root/__sdl_pending" not in vault(orchestrator).store
    await orchestrator.stop()


async def test_rejected_password_without_previous_needs_attention(
    orchestrator_factory: Any, hosts: FakeHosts
) -> None:
    orchestrator = orchestrator_factory(
        targets=[{"name": "vm1", "host": "vm1.test", "options": {"reject_all": True}}]
    )
    await orchestrator.start()
    run = await run_rollover(orchestrator)
    result = run.results[0]
    assert result.status == TargetStatus.NEEDS_ATTENTION
    assert "linux/vm1/root/__sdl_pending" in (result.message or "")
    # The password set on the host is recoverable from the staging path.
    staged = vault(orchestrator).store["linux/vm1/root/__sdl_pending"][-1]
    assert staged.value.get_secret_value() == hosts.passwords["vm1.test"]
    assert staged.attributes["state"] == "pending"
    await orchestrator.stop()


async def test_store_failure_after_change_needs_attention(
    orchestrator_factory: Any, hosts: FakeHosts
) -> None:
    orchestrator = orchestrator_factory(
        targets=[{"name": "vm1", "host": "vm1.test"}],
        secrets_config={"fail_write_paths": ["linux/vm1/root"]},
    )
    await orchestrator.start()
    run = await run_rollover(orchestrator)
    result = run.results[0]
    assert result.status == TargetStatus.NEEDS_ATTENTION
    staged = vault(orchestrator).store["linux/vm1/root/__sdl_pending"][-1]
    assert staged.value.get_secret_value() == hosts.passwords["vm1.test"]
    await orchestrator.stop()


async def test_target_cannot_be_rolled_over_twice_at_once(orchestrator_factory: Any) -> None:
    orchestrator = orchestrator_factory()
    await orchestrator.start()
    first = await orchestrator.start_rollover(RolloverRequest(all=True, reason="a"), ALICE)
    with pytest.raises(RequestError, match="in progress"):
        await orchestrator.start_rollover(RolloverRequest(targets=["vm1"], reason="b"), ALICE)
    await orchestrator.wait(first.id, timeout=10)
    second = await orchestrator.start_rollover(RolloverRequest(targets=["vm1"], reason="c"), ALICE)
    await orchestrator.wait(second.id, timeout=10)
    await orchestrator.stop()


async def test_audit_log_covers_every_step_and_never_holds_passwords(
    orchestrator_factory: Any, hosts: FakeHosts, tmp_path: Any
) -> None:
    orchestrator = orchestrator_factory(
        targets=[
            {"name": "vm1", "host": "vm1.test"},
            {"name": "vm2", "host": "vm2.test", "options": {"reject_new": True}},
        ]
    )
    await orchestrator.start()
    await seed(orchestrator, hosts, "vm1", "old-password-one")
    await seed(orchestrator, hosts, "vm2", "old-password-two")
    run = await run_rollover(orchestrator)
    new_password = hosts.passwords["vm1.test"]
    await orchestrator.stop()

    log_text = (tmp_path / "audit.jsonl").read_text()
    for secret in (new_password, "old-password-one", "old-password-two"):
        assert secret not in log_text

    events = await orchestrator.audit.primary.query(AuditQuery(run_id=run.id, limit=1000))
    actions = [e.action for e in events if e.target == "vm1"]
    for step in (
        "connect",
        "preflight",
        "read_previous",
        "generate",
        "escrow",
        "change",
        "verify",
        "store",
    ):
        assert f"rollover.target.{step}" in actions
    assert events[0].action == "rollover.requested"
    assert events[0].actor.id == "alice"
    assert all(e.initiated_by and e.initiated_by.id == "alice" for e in events[1:])
    vm2_actions = [e.action for e in events if e.target == "vm2"]
    assert "rollover.target.rollback" in vm2_actions
    ok, detail = await orchestrator.audit.primary.verify()
    assert ok, detail
