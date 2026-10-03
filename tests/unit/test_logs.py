"""Reviewing the audit log (filters, facets) and closing gaps in what it records."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from sdl.api.app import create_app
from sdl.core.models import Actor, ActorType, AuditEvent, AuditQuery, Outcome
from sdl.core.module import InventoryModule, ModuleError
from sdl.core.orchestrator import Orchestrator
from tests.conftest import ADMIN_TOKEN, AUDITOR_TOKEN, OPERATOR_TOKEN


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def event(**kwargs: Any) -> AuditEvent:
    values: dict[str, Any] = {
        "actor": Actor.system(),
        "action": "rollover.target.change",
        "outcome": Outcome.SUCCESS,
    }
    values.update(kwargs)
    return AuditEvent(**values)


def test_query_matching() -> None:
    bob = Actor(type=ActorType.USER, id="bob")
    e = event(target="web1", module="linux", initiated_by=bob, message="Changed the password")
    assert AuditQuery().matches(e)
    assert AuditQuery(actions=["rollover"]).matches(e)
    assert AuditQuery(actions=["rollover.target"]).matches(e)
    assert not AuditQuery(actions=["rollover.tar"]).matches(e)
    assert AuditQuery(actions=["*.change"]).matches(e)
    assert AuditQuery(actions=["inventory", "rollover"]).matches(e)
    assert AuditQuery(targets=["web1", "web2"], modules=["linux"]).matches(e)
    assert not AuditQuery(targets=["web2"]).matches(e)
    assert AuditQuery(actors=["bob"]).matches(e), "done on bob's behalf"
    assert AuditQuery(actors=["orchestrator"]).matches(e)
    assert not AuditQuery(actors=["alice"]).matches(e)
    assert AuditQuery(outcomes=[Outcome.SUCCESS, Outcome.FAILURE]).matches(e)
    assert not AuditQuery(outcomes=[Outcome.FAILURE]).matches(e)
    assert AuditQuery(text="CHANGED password").matches(e)
    assert not AuditQuery(text="rollback").matches(e)
    hour = timedelta(hours=1)
    assert AuditQuery(since=e.ts, until=e.ts + hour).matches(e)
    assert not AuditQuery(until=e.ts).matches(e), "until is exclusive"
    assert not AuditQuery(since=e.ts + hour).matches(e)
    naive = AuditQuery(since=e.ts.replace(tzinfo=None) - hour)
    assert naive.since is not None and naive.since.tzinfo is UTC and naive.matches(e)


@pytest.fixture
def api(orchestrator_factory: Any, tmp_path: Path) -> Iterator[TestClient]:
    store = {"inventory": {"type": "inventory.store", "config": {"path": str(tmp_path / "i.json")}}}
    with TestClient(create_app(orchestrator_factory(extra_modules=store))) as client:
        yield client


def rollover(api: TestClient, token: str, **body: Any) -> dict[str, Any]:
    response = api.post(
        "/api/v1/rollovers?wait=true", json={"reason": "test", **body}, headers=auth(token)
    )
    assert response.status_code == 202, response.text
    run: dict[str, Any] = response.json()
    return run


def audit(api: TestClient, query: str = "") -> list[dict[str, Any]]:
    response = api.get(f"/api/v1/audit?limit=10000&{query}", headers=auth(AUDITOR_TOKEN))
    assert response.status_code == 200, response.text
    events: list[dict[str, Any]] = response.json()
    return events


def test_filter_by_system_action_user_and_date(api: TestClient) -> None:
    before = datetime.now(UTC)
    rollover(api, OPERATOR_TOKEN, targets=["vm1"])
    rollover(api, ADMIN_TOKEN, targets=["vm2"], dry_run=True)

    vm1 = audit(api, "target=vm1")
    assert vm1 and {e["target"] for e in vm1} == {"vm1"}
    assert [e["action"] for e in vm1][-1] == "rollover.target"

    changes = audit(api, "target=vm1&target=vm2&action=rollover.target.change")
    assert {e["target"] for e in changes} == {"vm1"}, "the dry run changed nothing"

    by_bob = audit(api, "actor=bob&action=rollover")
    assert by_bob and {e["target"] for e in by_bob if e["target"]} == {"vm1"}
    assert all(e["actor"]["id"] == "bob" or e["initiated_by"]["id"] == "bob" for e in by_bob), (
        "system steps done on bob's behalf are included"
    )

    outcomes = {e["outcome"] for e in audit(api, "outcome=success&outcome=started")}
    assert outcomes == {"success", "started"}

    after = datetime.now(UTC)
    window = f"since={before.isoformat()}&until={after.isoformat()}".replace("+", "%2B")
    assert len(audit(api, window)) > 10
    assert audit(api, f"until={before.isoformat()}".replace("+", "%2B"))[-1]["action"] == (
        "system.start"
    )
    later = audit(api, f"since={after.isoformat()}".replace("+", "%2B"))
    assert {e["action"] for e in later} == {"api.request"}, "only the reads since then"

    newest = audit(api, "order=newest&limit=2")
    oldest = audit(api, "limit=2")
    assert len(newest) == 2 and newest[0]["ts"] >= newest[1]["ts"]
    assert len(oldest) == 2 and oldest[0]["ts"] <= oldest[1]["ts"]
    # Each read is recorded before it runs, so it is the most recent event it returns.
    assert newest[0]["details"]["query"].endswith("order=newest&limit=2")
    assert oldest[1]["details"]["query"].endswith("&limit=2")
    assert audit(api, "q=dry")[0]["action"] == "rollover.target"

    assert api.get("/api/v1/audit?outcome=bogus", headers=auth(ADMIN_TOKEN)).status_code == 422
    assert api.get("/api/v1/audit?target=vm1", headers=auth(OPERATOR_TOKEN)).status_code == 403


def test_facets_list_what_can_be_filtered(api: TestClient) -> None:
    rollover(api, OPERATOR_TOKEN, targets=["vm1"])
    facets = api.get("/api/v1/audit/facets", headers=auth(AUDITOR_TOKEN)).json()
    assert facets["events"] > 0 and facets["first"] <= facets["last"]
    assert set(facets["targets"]) == {"vm1"}
    assert {"bob", "orchestrator", "carol"} <= set(facets["actors"])
    assert "rollover.target.change" in facets["actions"]
    assert "linux" in facets["modules"]


def test_reading_the_log_is_itself_recorded_with_its_filters(api: TestClient) -> None:
    audit(api, "target=vm3&action=inventory")
    reads = audit(api, "action=api.request&actor=carol")
    assert reads[0]["message"] == "GET /api/v1/audit"
    assert reads[0]["details"]["query"] == "limit=10000&target=vm3&action=inventory"


def test_requests_that_fail_after_authorization_are_recorded(api: TestClient) -> None:
    admin = auth(ADMIN_TOKEN)
    bad = {"name": "web1", "secret_path": "x", "host": "h", "module": "nope"}
    assert api.put("/api/v1/inventory/inventory/systems/web1", json=bad, headers=admin).status_code
    assert api.delete("/api/v1/inventory/inventory/systems/ghost", headers=admin).status_code == 404
    body = {"targets": ["nope"], "reason": "r"}
    assert api.post("/api/v1/rollovers", json=body, headers=auth(OPERATOR_TOKEN)).status_code == 400
    failures = audit(api, "action=api.request&outcome=failure")
    assert [(e["actor"]["id"], e["message"], e["details"]["status"]) for e in failures] == [
        ("alice", "PUT /api/v1/inventory/inventory/systems/web1", 400),
        ("alice", "DELETE /api/v1/inventory/inventory/systems/ghost", 404),
        ("bob", "POST /api/v1/rollovers", 400),
    ]
    # Rejected callers are recorded once, by authentication or authorization.
    api.get("/api/v1/audit", headers=auth("wrong"))
    api.get("/api/v1/audit", headers=auth(OPERATOR_TOKEN))
    assert len(audit(api, "action=api.request&outcome=failure")) == 3
    assert len(audit(api, "action=api.authenticate&action=api.authorize")) == 2


class FlakyInventory(InventoryModule):
    down = False

    async def list_systems(self) -> list[Any]:
        if FlakyInventory.down:
            raise ModuleError("CMDB is unreachable")
        return []

    async def refresh(self) -> None:
        if FlakyInventory.down:
            raise ModuleError("CMDB refused the refresh")


async def test_inventory_outages_are_recorded_once_each(orchestrator_factory: Any) -> None:
    orchestrator: Orchestrator = orchestrator_factory(
        extra_modules={"cmdb": {"type": "tests.unit.test_logs:FlakyInventory"}}
    )
    await orchestrator.start()
    try:
        FlakyInventory.down = True
        await orchestrator.inventory()
        await orchestrator.inventory()
        with pytest.raises(ModuleError):
            await orchestrator.refresh_inventory(Actor(type=ActorType.USER, id="alice"))
        FlakyInventory.down = False
        await orchestrator.inventory()
        await orchestrator.inventory()
        events = await orchestrator.audit.primary.query(
            AuditQuery(modules=["cmdb"], actions=["inventory"])
        )
        assert [(e.action, e.outcome) for e in events] == [
            ("inventory.unavailable", Outcome.FAILURE),
            ("inventory.refresh", Outcome.FAILURE),
            ("inventory.available", Outcome.SUCCESS),
        ]
        assert events[0].message == "CMDB is unreachable"
        assert events[1].actor.id == "alice"
    finally:
        FlakyInventory.down = False
        await orchestrator.stop()


async def test_a_module_that_fails_to_start_is_recorded(orchestrator_factory: Any) -> None:
    orchestrator: Orchestrator = orchestrator_factory(
        extra_modules={"siem": {"type": "forwarder.fake", "config": {"fail_start": True}}}
    )
    with pytest.raises(ModuleError):
        await orchestrator.start()
    [failed] = await orchestrator.audit.primary.query(AuditQuery(actions=["module.start"]))
    assert failed.outcome == Outcome.FAILURE and failed.module == "siem"
    assert failed.details["type"] == "forwarder.fake"
    assert "certificate" in (failed.message or "")
