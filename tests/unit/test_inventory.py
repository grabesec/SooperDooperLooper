from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from sdl.core.models import (
    Actor,
    ActorType,
    RolloverRequest,
    SecretRecord,
    ServiceAccount,
    TargetSpec,
    TargetStatus,
)
from sdl.core.module import InventoryModule, ModuleError
from sdl.core.orchestrator import (
    CONFIG_INVENTORY,
    ConfigError,
    ConflictError,
    NotFoundError,
    Orchestrator,
    RequestError,
)
from sdl.modules.inventory_store import StoreInventoryModule
from tests.conftest import FakeHosts, FakeSecretsModule, make_registry, make_settings

ALICE = Actor(type=ActorType.USER, id="alice", roles=["admin"])


class BrokenInventory(InventoryModule):
    async def list_systems(self) -> list[TargetSpec]:
        raise ModuleError("netbox.example.com: connection refused")


def store_modules(tmp_path: Path) -> dict[str, Any]:
    return {
        "inventory": {"type": "inventory.store", "config": {"path": str(tmp_path / "inv.json")}}
    }


def web(name: str, **extra: Any) -> TargetSpec:
    fields: dict[str, Any] = {
        "name": name,
        "hostname": name,
        "fqdn": f"{name}.example.com",
        "addresses": ["10.0.0.5"],
        "secret_path": f"linux/{name}/root",
        "groups": ["web"],
    }
    return TargetSpec.model_validate({**fields, **extra})


@pytest.fixture
async def orchestrator(tmp_path: Path) -> Any:
    registry = make_registry()
    registry.register("inventory.broken", BrokenInventory)
    settings = make_settings(tmp_path, extra_modules=store_modules(tmp_path))
    orch = Orchestrator(settings, registry=registry)
    await orch.start()
    yield orch
    await orch.stop()


def vault(orchestrator: Orchestrator) -> FakeSecretsModule:
    module = orchestrator.modules["vault"]
    assert isinstance(module, FakeSecretsModule)
    return module


# -- the system model ------------------------------------------------------------


def test_host_is_derived_from_fqdn_then_ip_then_hostname() -> None:
    assert web("a").host == "a.example.com"
    assert web("a", fqdn=None).host == "10.0.0.5"
    assert web("a", fqdn=None, addresses=[]).host == "a"
    assert web("a", host="192.0.2.1").host == "192.0.2.1"
    with pytest.raises(ValidationError, match="needs a host"):
        TargetSpec(name="x", secret_path="p")


def test_addresses_must_be_ip_addresses() -> None:
    assert web("a", addresses=[" 2001:DB8::1 "]).addresses == ["2001:db8::1"]
    with pytest.raises(ValidationError):
        web("a", addresses=["not-an-ip"])


# -- the built-in store ------------------------------------------------------------


async def test_store_persists_systems_across_restarts(tmp_path: Path) -> None:
    from sdl.core.audit import AuditRecorder
    from sdl.core.module import ModuleContext
    from sdl.modules.inventory_store import StoreInventoryConfig

    path = tmp_path / "sub" / "inventory.json"

    def make() -> StoreInventoryModule:
        return StoreInventoryModule(
            StoreInventoryConfig(path=path), ModuleContext("inventory", AuditRecorder())
        )

    store = make()
    await store.start()
    assert await store.list_systems() == []
    await store.put_system(web("web1"))
    await store.put_system(web("web2", host="192.0.2.2"))
    assert await store.delete_system("web2") is True
    assert await store.delete_system("web2") is False
    await store.put_system(web("web3", host="192.0.2.3"))

    on_disk = json.loads(path.read_text())
    assert path.stat().st_mode & 0o777 == 0o600
    by_name = {s["name"]: s for s in on_disk["systems"]}
    assert "host" not in by_name["web1"]  # derived from the FQDN, so not pinned
    assert by_name["web3"]["host"] == "192.0.2.3"

    again = make()
    await again.start()
    systems = {s.name: s for s in await again.list_systems()}
    assert set(systems) == {"web1", "web3"}
    assert systems["web1"].host == "web1.example.com"
    assert systems["web1"].addresses == ["10.0.0.5"]


async def test_store_rejects_a_corrupt_file(tmp_path: Path) -> None:
    from sdl.core.audit import AuditRecorder
    from sdl.core.module import ModuleContext
    from sdl.modules.inventory_store import StoreInventoryConfig

    path = tmp_path / "inventory.json"
    path.write_text("{not json")
    store = StoreInventoryModule(
        StoreInventoryConfig(path=path), ModuleContext("inventory", AuditRecorder())
    )
    with pytest.raises(ModuleError, match="cannot read inventory"):
        await store.start()


# -- merging inventories ---------------------------------------------------------------


async def test_inventory_merges_config_and_store(orchestrator: Orchestrator) -> None:
    await orchestrator.put_system("inventory", web("web1"), ALICE)
    inventory = await orchestrator.inventory()
    assert [(s.name, s.source) for s in inventory.systems] == [
        ("vm1", CONFIG_INVENTORY),
        ("vm2", CONFIG_INVENTORY),
        ("vm3", CONFIG_INVENTORY),
        ("web1", "inventory"),
    ]
    sources = {s.id: s for s in inventory.sources}
    assert sources[CONFIG_INVENTORY].systems == 3 and not sources[CONFIG_INVENTORY].writable
    assert sources["inventory"].systems == 1 and sources["inventory"].writable


async def test_duplicate_names_keep_the_first_inventory(orchestrator: Orchestrator) -> None:
    store = orchestrator.modules["inventory"]
    assert isinstance(store, StoreInventoryModule)
    await store.put_system(web("vm1"))  # bypasses the orchestrator's conflict check
    inventory = await orchestrator.inventory()
    assert [s.source for s in inventory.systems if s.name == "vm1"] == [CONFIG_INVENTORY]
    assert {s.id: s.skipped for s in inventory.sources}["inventory"] == ["vm1"]


async def test_unavailable_inventory_is_reported_and_others_still_work(tmp_path: Path) -> None:
    registry = make_registry()
    registry.register("inventory.broken", BrokenInventory)
    settings = make_settings(
        tmp_path, extra_modules={"netbox": {"type": "inventory.broken"}, **store_modules(tmp_path)}
    )
    orchestrator = Orchestrator(settings, registry=registry)
    await orchestrator.start()
    inventory = await orchestrator.inventory()
    netbox = next(s for s in inventory.sources if s.id == "netbox")
    assert not netbox.ok and "connection refused" in (netbox.error or "")
    assert len(inventory.systems) == 3

    with pytest.raises(RequestError, match="unavailable inventories: netbox"):
        await orchestrator.select_targets(RolloverRequest(targets=["nb1"], reason="r"))
    run = await orchestrator.start_rollover(RolloverRequest(targets=["vm1"], reason="r"), ALICE)
    assert (await orchestrator.wait(run.id, 10)).results[0].status == TargetStatus.SUCCEEDED
    await orchestrator.stop()


def test_reserved_inventory_id(tmp_path: Path) -> None:
    settings = make_settings(
        tmp_path,
        extra_modules={CONFIG_INVENTORY: {"type": "inventory.store", "config": {"path": "x"}}},
    )
    with pytest.raises(ConfigError, match="reserved"):
        Orchestrator(settings, registry=make_registry()).load()


# -- editing the inventory ------------------------------------------------------------------


async def test_put_system_checks_it_can_be_rolled_over(orchestrator: Orchestrator) -> None:
    with pytest.raises(RequestError, match="'nope' is not a configured target module"):
        await orchestrator.put_system("inventory", web("web1", module="nope"), ALICE)
    bad_account = web(
        "web1", service_account={"username": "svc", "credential_path": "p", "secrets": "nope"}
    )
    with pytest.raises(RequestError, match="'nope' is not a configured secrets module"):
        await orchestrator.put_system("inventory", bad_account, ALICE)
    with pytest.raises(ConflictError, match=r"already comes from inventory 'sdl\.yaml'"):
        await orchestrator.put_system("inventory", web("vm1"), ALICE)
    with pytest.raises(NotFoundError):
        await orchestrator.put_system("nope", web("web1"), ALICE)
    assert (await orchestrator.inventory()).systems[-1].name == "vm3"


async def test_inventory_changes_are_audited(orchestrator: Orchestrator) -> None:
    await orchestrator.put_system("inventory", web("web1"), ALICE)
    await orchestrator.put_system("inventory", web("web1", groups=["db"]), ALICE)
    await orchestrator.delete_system("inventory", "web1", ALICE)
    with pytest.raises(NotFoundError):
        await orchestrator.delete_system("inventory", "web1", ALICE)
    events = await orchestrator.audit.primary.query(target="web1")
    assert [(e.action, e.actor.id) for e in events] == [
        ("inventory.system.add", "alice"),
        ("inventory.system.update", "alice"),
        ("inventory.system.delete", "alice"),
    ]
    assert events[0].details["system"]["fqdn"] == "web1.example.com"


# -- rolling over inventory systems with their service accounts ----------------------


async def test_rollover_signs_in_with_the_systems_service_account(
    orchestrator: Orchestrator, hosts: FakeHosts
) -> None:
    account = ServiceAccount(
        username="sdl-web", credential_path="svc/web1", credential_type="password"
    )
    system = web("web1", service_account=account, options={"service_secret": "svc-pass"})
    await orchestrator.put_system("inventory", system, ALICE)
    await orchestrator.put_system("inventory", web("web2", addresses=["10.0.0.6"]), ALICE)
    await vault(orchestrator).write("svc/web1", SecretRecord(value=SecretStr("svc-pass")))

    run = await orchestrator.start_rollover(
        RolloverRequest(targets=["web1", "web2"], reason="r"), ALICE
    )
    run = await orchestrator.wait(run.id, 10)
    results = {r.target: r for r in run.results}
    assert results["web1"].status == TargetStatus.SUCCEEDED, results["web1"].message
    assert results["web1"].source == "inventory"
    assert results["web1"].steps[1].name == "service_account"
    assert hosts.logins == [("web1.example.com", "sdl-web", "password")]
    assert results["web2"].status == TargetStatus.SUCCEEDED
    assert "service_account" not in [s.name for s in results["web2"].steps]

    log_text = (orchestrator.audit.primary.config.path).read_text()  # type: ignore[attr-defined]
    assert "svc-pass" not in log_text


async def test_missing_service_account_credential_fails_before_connecting(
    orchestrator: Orchestrator, hosts: FakeHosts
) -> None:
    account = ServiceAccount(username="sdl-web", credential_path="svc/missing")
    await orchestrator.put_system("inventory", web("web1", service_account=account), ALICE)
    run = await orchestrator.start_rollover(RolloverRequest(targets=["web1"], reason="r"), ALICE)
    result = (await orchestrator.wait(run.id, 10)).results[0]
    assert result.status == TargetStatus.FAILED
    assert "no credential for service account 'sdl-web' at svc/missing" in (result.message or "")
    assert [s.name for s in result.steps] == ["start", "service_account"]
    assert hosts.logins == [] and hosts.change_calls == {}


async def test_systems_cannot_change_while_being_rolled_over(orchestrator: Orchestrator) -> None:
    await orchestrator.put_system("inventory", web("web1"), ALICE)
    run = await orchestrator.start_rollover(RolloverRequest(targets=["web1"], reason="r"), ALICE)
    with pytest.raises(ConflictError, match="in progress"):
        await orchestrator.delete_system("inventory", "web1", ALICE)
    await orchestrator.wait(run.id, 10)
    await orchestrator.delete_system("inventory", "web1", ALICE)
