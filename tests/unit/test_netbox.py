from __future__ import annotations

from typing import Any

import httpx
import pytest

from sdl.core.audit import AuditRecorder
from sdl.core.models import AuditEvent, AuditQuery
from sdl.core.module import AuditModule, ModuleConfig, ModuleContext, ModuleError
from sdl.modules.inventory_netbox import NetBoxConfig, NetBoxInventoryModule

VMS = [
    {
        "id": 1,
        "name": "web1",
        "status": {"value": "active"},
        "site": {"slug": "ams1", "name": "Amsterdam 1"},
        "role": {"slug": "web"},
        "primary_ip4": {"address": "10.0.0.11/24", "dns_name": "web1.prod.example.com"},
        "primary_ip6": {"address": "2001:db8::11/64", "dns_name": ""},
        "tags": [{"slug": "sdl"}, {"slug": "prod"}],
        "custom_fields": {},
        "description": "front end",
    },
    {
        "id": 2,
        "name": "db1",
        "site": {"slug": "ams1"},
        "role": None,
        "primary_ip4": {"address": "10.0.0.21/24", "dns_name": ""},
        "primary_ip6": None,
        "tags": [],
        "custom_fields": {
            "sdl_account": "postgres-admin",
            "sdl_port": 2222,
            "sdl_secret_path": "db/db1/admin",
            "sdl_service_account": "dbsvc",
            "sdl_service_account_path": "svc/db1",
        },
    },
    {"id": 3, "name": "no-ip", "primary_ip4": None, "primary_ip6": None, "tags": []},
]
DEVICES = [
    {
        "id": 7,
        "name": "fw1.edge.example.com",
        "device_role": {"slug": "firewall"},
        "primary_ip4": {"address": "192.0.2.1/32"},
        "primary_ip6": None,
        "tags": [],
    }
]


class FakeNetBox:
    def __init__(self, token: str = "nb-token") -> None:  # noqa: S107
        self.token = token
        self.calls: list[httpx.Request] = []
        self.down = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if self.down:
            return httpx.Response(503)
        scheme = "Bearer" if self.token.startswith("nbt_") else "Token"
        if request.headers.get("authorization") != f"{scheme} {self.token}":
            return httpx.Response(403, json={"detail": "Invalid token"})
        path = request.url.path
        if path == "/api/status/":
            return httpx.Response(200, json={"netbox-version": "4.3.2"})
        if path == "/api/virtualization/virtual-machines/":
            # Two pages, to exercise pagination. NetBox behind a proxy often names
            # its internal address in "next"; SDL must keep talking to netbox.test.
            offset = int(request.url.params.get("offset", "0"))
            page = VMS[offset : offset + 2]
            next_url = (
                f"http://netbox-internal:8080{path}?limit=2&offset={offset + 2}"
                if offset + 2 < len(VMS)
                else None
            )
            return httpx.Response(200, json={"count": len(VMS), "next": next_url, "results": page})
        if path == "/api/dcim/devices/":
            return httpx.Response(200, json={"count": 1, "next": None, "results": DEVICES})
        return httpx.Response(404)


class MemoryAudit(AuditModule):
    def __init__(self) -> None:
        super().__init__(ModuleConfig(), ModuleContext("memory", AuditRecorder()))
        self.events: list[AuditEvent] = []

    async def write(self, event: AuditEvent) -> AuditEvent:
        self.events.append(event)
        return event

    async def query(self, query: AuditQuery) -> list[AuditEvent]:
        return [e for e in self.events if query.matches(e)][-query.limit :]


async def make(
    netbox: FakeNetBox, monkeypatch: pytest.MonkeyPatch, **config: Any
) -> NetBoxInventoryModule:
    monkeypatch.setenv("NETBOX_TOKEN", netbox.token)
    module = NetBoxInventoryModule(
        NetBoxConfig.model_validate({"url": "http://netbox.test", **config}),
        ModuleContext("netbox", AuditRecorder([MemoryAudit()])),
    )
    module._transport = httpx.MockTransport(netbox.handler)
    await module.start()
    return module


async def test_maps_virtual_machines_to_systems(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = FakeNetBox()
    module = await make(
        netbox,
        monkeypatch,
        page_size=2,
        group_by=["tags", "site", "role"],
        defaults={
            "secret_path": "linux/{site}/{name}/{account}",
            "service_account": {"username": "sdl-svc", "credential_path": "svc/{name}"},
        },
    )
    systems = {s.name: s for s in await module.list_systems()}
    assert set(systems) == {"web1", "db1"}
    assert module.skipped == {"no-ip": "no primary IP address"}
    [audit] = module.context.audit._modules
    assert isinstance(audit, MemoryAudit)
    [event] = [e for e in audit.events if e.action == "inventory.objects_skipped"]
    assert event.module == "netbox" and event.details["objects"] == module.skipped

    web1 = systems["web1"]
    assert web1.hostname == "web1"
    assert web1.fqdn == "web1.prod.example.com"
    assert web1.addresses == ["10.0.0.11", "2001:db8::11"]
    assert web1.host == "10.0.0.11"
    assert web1.account == "root"
    assert web1.secret_path == "linux/ams1/web1/root"
    assert web1.service_account is not None
    assert web1.service_account.username == "sdl-svc"
    assert web1.service_account.credential_path == "svc/web1"
    assert web1.groups == ["prod", "role:web", "sdl", "site:ams1"]
    assert web1.description == "front end"

    db1 = systems["db1"]  # custom fields override the defaults
    assert db1.fqdn is None
    assert db1.account == "postgres-admin"
    assert db1.port == 2222
    assert db1.secret_path == "db/db1/admin"
    assert db1.service_account is not None
    assert db1.service_account.username == "dbsvc"
    assert db1.service_account.credential_path == "svc/db1"

    first = netbox.calls[0].url
    assert first.params["status"] == "active" and first.params["limit"] == "2"
    assert len(netbox.calls) == 2
    assert {c.url.host for c in netbox.calls} == {"netbox.test"}
    await module.stop()


async def test_devices_fqdn_and_connect_via(monkeypatch: pytest.MonkeyPatch) -> None:
    module = await make(
        FakeNetBox(),
        monkeypatch,
        objects=["devices"],
        connect_via="fqdn",
        group_by=["role"],
        filters={"tag": ["sdl", "linux"]},
    )
    [fw1] = await module.list_systems()
    assert fw1.fqdn == fw1.host == "fw1.edge.example.com"
    assert fw1.hostname == "fw1"
    assert fw1.secret_path == "device/fw1.edge.example.com/root"
    assert fw1.groups == ["role:firewall"]
    assert fw1.service_account is None


async def test_domain_completes_short_names(monkeypatch: pytest.MonkeyPatch) -> None:
    module = await make(FakeNetBox(), monkeypatch, domain="corp.example.com")
    systems = {s.name: s for s in await module.list_systems()}
    assert systems["db1"].fqdn == "db1.corp.example.com"
    assert systems["web1"].fqdn == "web1.prod.example.com"  # DNS name in NetBox wins


async def test_results_are_cached_until_refresh(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = FakeNetBox()
    module = await make(netbox, monkeypatch, cache_ttl=3600)
    await module.list_systems()
    calls = len(netbox.calls)
    await module.list_systems()
    assert len(netbox.calls) == calls
    await module.refresh()
    await module.list_systems()
    assert len(netbox.calls) > calls


async def test_v2_tokens_use_bearer(monkeypatch: pytest.MonkeyPatch) -> None:
    module = await make(FakeNetBox(token="nbt_abc.def"), monkeypatch)
    assert len(await module.list_systems()) == 2
    assert (await module.health())["netbox_version"] == "4.3.2"


async def test_errors_are_module_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    netbox = FakeNetBox()
    module = await make(netbox, monkeypatch)
    netbox.down = True
    with pytest.raises(ModuleError, match="HTTP 503"):
        await module.list_systems()
    assert (await module.health())["ok"] is False
    monkeypatch.delenv("NETBOX_TOKEN")
    with pytest.raises(ModuleError, match="NETBOX_TOKEN is not set"):
        await module.list_systems()


def test_templates_only_take_known_fields() -> None:
    with pytest.raises(ValueError, match="use only"):
        NetBoxConfig.model_validate({"url": "x", "defaults": {"secret_path": "{name.__class__}"}})
    with pytest.raises(ValueError, match="use only"):
        NetBoxConfig.model_validate({"url": "x", "defaults": {"secret_path": "{password}"}})
