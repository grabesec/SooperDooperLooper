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


@pytest.fixture
def inventory_api(orchestrator_factory: Any, tmp_path: Any) -> Iterator[TestClient]:
    store = {"inventory": {"type": "inventory.store", "config": {"path": str(tmp_path / "i.json")}}}
    with TestClient(create_app(orchestrator_factory(extra_modules=store))) as client:
        yield client


WEB1 = {
    "name": "web1",
    "hostname": "web1",
    "fqdn": "web1.example.com",
    "addresses": ["10.0.0.11"],
    "secret_path": "linux/web1/root",
    "groups": ["web", "prod"],
}


def test_store_systems_and_list_them(inventory_api: TestClient) -> None:
    admin = auth(ADMIN_TOKEN)
    url = "/api/v1/inventory/inventory/systems/web1"
    assert inventory_api.put(url, json=WEB1, headers=auth(OPERATOR_TOKEN)).status_code == 403
    response = inventory_api.put(url, json=WEB1, headers=admin)
    assert response.status_code == 200, response.text
    assert response.json()["host"] == "web1.example.com"
    assert response.json()["source"] == "inventory"

    listing = inventory_api.get("/api/v1/systems", headers=auth(OPERATOR_TOKEN)).json()
    assert [s["name"] for s in listing["systems"]] == ["vm1", "vm2", "vm3", "web1"]
    assert {s["id"]: s["writable"] for s in listing["sources"]} == {
        "sdl.yaml": False,
        "inventory": True,
    }
    filtered = inventory_api.get("/api/v1/systems?q=10.0.0.11", headers=auth(OPERATOR_TOKEN)).json()
    assert [s["name"] for s in filtered["systems"]] == ["web1"]
    by_group = inventory_api.get("/api/v1/systems?group=web&source=sdl.yaml", headers=admin)
    assert [s["name"] for s in by_group.json()["systems"]] == ["vm1", "vm2"]
    assert inventory_api.get("/api/v1/systems/web1", headers=admin).json()["fqdn"] == (
        "web1.example.com"
    )
    assert inventory_api.get("/api/v1/systems/nope", headers=admin).status_code == 404
    assert len(inventory_api.get("/api/v1/targets", headers=admin).json()) == 4


def test_inventory_write_errors(inventory_api: TestClient) -> None:
    admin = auth(ADMIN_TOKEN)
    base = "/api/v1/inventory"
    assert (
        inventory_api.put(f"{base}/inventory/systems/other", json=WEB1, headers=admin).status_code
        == 400
    )
    assert (
        inventory_api.put(f"{base}/nope/systems/web1", json=WEB1, headers=admin).status_code == 404
    )
    assert (
        inventory_api.put(f"{base}/sdl.yaml/systems/web1", json=WEB1, headers=admin).status_code
        == 404
    )
    vm1 = {**WEB1, "name": "vm1"}
    assert (
        inventory_api.put(f"{base}/inventory/systems/vm1", json=vm1, headers=admin).status_code
        == 409
    )
    bad = {**WEB1, "module": "nope"}
    response = inventory_api.put(f"{base}/inventory/systems/web1", json=bad, headers=admin)
    assert response.status_code == 400 and "nope" in response.json()["detail"]
    no_address = {"name": "web1", "secret_path": "x"}
    assert (
        inventory_api.put(
            f"{base}/inventory/systems/web1", json=no_address, headers=admin
        ).status_code
        == 422
    )
    assert inventory_api.delete(f"{base}/inventory/systems/web1", headers=admin).status_code == 404


def test_roll_over_selected_systems_and_see_each_result(inventory_api: TestClient) -> None:
    admin = auth(ADMIN_TOKEN)
    inventory_api.put("/api/v1/inventory/inventory/systems/web1", json=WEB1, headers=admin)
    run = inventory_api.post(
        "/api/v1/rollovers?wait=true",
        json={"targets": ["web1", "vm3"], "reason": "picked in the UI"},
        headers=auth(OPERATOR_TOKEN),
    ).json()
    assert run["status"] == "succeeded"
    results = {r["target"]: r for r in run["results"]}
    assert set(results) == {"web1", "vm3"}
    assert (
        results["web1"]["source"] == "inventory" and results["web1"]["host"] == "web1.example.com"
    )
    assert all(r["status"] == "succeeded" and r["steps"] for r in results.values())

    deleted = inventory_api.delete("/api/v1/inventory/inventory/systems/web1", headers=admin)
    assert deleted.status_code == 204
    events = inventory_api.get("/api/v1/audit?target=web1", headers=admin).json()
    actions = [e["action"] for e in events]
    assert actions[0] == "inventory.system.add" and actions[-1] == "inventory.system.delete"


def test_refresh_and_inventory_status(inventory_api: TestClient) -> None:
    sources = inventory_api.post("/api/v1/inventory/refresh", headers=auth(ADMIN_TOKEN)).json()
    refresh = inventory_api.post("/api/v1/inventory/refresh", headers=auth(OPERATOR_TOKEN))
    assert refresh.status_code == 403
    assert [s["id"] for s in sources] == ["sdl.yaml", "inventory"]
    assert inventory_api.get("/api/v1/inventory", headers=auth(AUDITOR_TOKEN)).status_code == 200


def test_me_reports_permissions(api: TestClient) -> None:
    me = api.get("/api/v1/me", headers=auth(OPERATOR_TOKEN)).json()
    assert me["actor"]["id"] == "bob"
    assert "rollover:run" in me["permissions"] and "inventory:write" not in me["permissions"]


def test_web_page_is_served_with_a_strict_policy(api: TestClient) -> None:
    assert api.get("/", follow_redirects=False).headers["location"] == "/ui/"
    page = api.get("/ui/")
    assert page.status_code == 200 and page.headers["content-type"].startswith("text/html")
    assert "script-src 'self'" in page.headers["content-security-policy"]
    assert '<script src="/ui/app.js"' in page.text
    assert api.get("/ui/app.js").headers["content-type"].startswith("text/javascript")
    assert api.get("/ui/app.css").status_code == 200
    assert api.get("/ui/../app.py").status_code == 404
    assert api.get("/ui/secret.txt").status_code == 404
