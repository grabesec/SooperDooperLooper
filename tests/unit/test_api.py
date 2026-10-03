from __future__ import annotations

import time
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from sdl.api.app import create_app
from tests.conftest import ADMIN_TOKEN, AUDITOR_TOKEN, OPERATOR_TOKEN


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def api(orchestrator_factory: Any) -> Iterator[TestClient]:
    with TestClient(create_app(orchestrator_factory())) as client:
        yield client


def test_health_needs_no_auth(api: TestClient) -> None:
    assert api.get("/health").json()["status"] == "ok"


def test_requests_without_valid_token_are_rejected_and_audited(api: TestClient) -> None:
    assert api.get("/api/v1/targets").status_code == 401
    assert api.get("/api/v1/targets", headers=auth("wrong")).status_code == 401
    events = api.get("/api/v1/audit", headers=auth(ADMIN_TOKEN)).json()
    denied = [e for e in events if e["action"] == "api.authenticate"]
    assert len(denied) == 2 and all(e["outcome"] == "denied" for e in denied)


def test_roles_limit_what_callers_can_do(api: TestClient) -> None:
    body = {"all": True, "reason": "x", "dry_run": True}
    assert api.post("/api/v1/rollovers", json=body, headers=auth(AUDITOR_TOKEN)).status_code == 403
    assert api.get("/api/v1/audit", headers=auth(OPERATOR_TOKEN)).status_code == 403
    assert api.get("/api/v1/audit", headers=auth(AUDITOR_TOKEN)).status_code == 200
    events = api.get("/api/v1/audit", headers=auth(ADMIN_TOKEN)).json()
    assert any(e["action"] == "api.authorize" and e["actor"]["id"] == "carol" for e in events)


def test_run_rollover_and_read_report(api: TestClient) -> None:
    response = api.post(
        "/api/v1/rollovers?wait=true",
        json={"groups": ["web"], "reason": "rotate web"},
        headers=auth(OPERATOR_TOKEN),
    )
    assert response.status_code == 202
    run = response.json()
    assert run["status"] == "succeeded"
    assert run["requested_by"]["id"] == "bob"
    assert sorted(r["target"] for r in run["results"]) == ["vm1", "vm2"]
    assert all(r["status"] == "succeeded" and r["secret_version"] == "1" for r in run["results"])

    fetched = api.get(f"/api/v1/rollovers/{run['id']}", headers=auth(OPERATOR_TOKEN)).json()
    assert fetched["id"] == run["id"]
    listed = api.get("/api/v1/rollovers", headers=auth(OPERATOR_TOKEN)).json()
    assert [r["id"] for r in listed] == [run["id"]]

    events = api.get(f"/api/v1/audit?run_id={run['id']}", headers=auth(ADMIN_TOKEN)).json()
    assert events[0]["action"] == "rollover.requested"
    assert events[-1]["action"] == "rollover.run" and events[-1]["outcome"] == "success"
    assert api.get("/api/v1/audit/verify", headers=auth(ADMIN_TOKEN)).json()["ok"] is True


def test_run_without_wait_can_be_polled(api: TestClient) -> None:
    run = api.post(
        "/api/v1/rollovers", json={"all": True, "reason": "r"}, headers=auth(OPERATOR_TOKEN)
    ).json()
    for _ in range(50):
        run = api.get(f"/api/v1/rollovers/{run['id']}", headers=auth(OPERATOR_TOKEN)).json()
        if run["status"] not in ("pending", "running"):
            break
        time.sleep(0.05)
    assert run["status"] == "succeeded"


def test_bad_requests(api: TestClient) -> None:
    headers = auth(OPERATOR_TOKEN)
    assert (
        api.post(
            "/api/v1/rollovers", json={"targets": ["nope"], "reason": "r"}, headers=headers
        ).status_code
        == 400
    )
    assert (
        api.post("/api/v1/rollovers", json={"all": True, "reason": ""}, headers=headers).status_code
        == 422
    )
    assert api.get("/api/v1/rollovers/does-not-exist", headers=headers).status_code == 404


def test_modules_endpoint(api: TestClient) -> None:
    modules = api.get("/api/v1/modules", headers=auth(ADMIN_TOKEN)).json()
    assert {m["id"]: m["kind"] for m in modules} == {
        "audit": "audit",
        "auth": "auth",
        "passwords": "generator",
        "vault": "secrets",
        "linux": "target",
    }
