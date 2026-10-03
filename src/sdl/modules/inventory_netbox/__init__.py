"""Read-only inventory that takes systems from NetBox.

Virtual machines (and, optionally, devices) are read through NetBox's REST
API and turned into SDL systems: the object's name becomes the system name and
hostname, its primary IPv4/IPv6 addresses the system's addresses, and the
primary IP's DNS name (or the name plus ``domain``) its FQDN.

What NetBox does not know (which account to roll over, where its credential
lives in the secrets module, the service account SDL signs in with) comes from
this module's ``defaults``. Templates such as ``"linux/{name}/{account}"`` are
filled in per system, and NetBox custom fields override any default per object:

=================================  =========================================
custom field                       overrides
=================================  =========================================
``sdl_account``                    ``account``
``sdl_port``                       ``port``
``sdl_secret_path``                ``secret_path``
``sdl_target_module``              ``module``
``sdl_service_account``            the service account's ``username``
``sdl_service_account_path``       the service account's ``credential_path``
=================================  =========================================

Results are cached for ``cache_ttl`` seconds; ``POST /api/v1/inventory/refresh``
(``sdl systems refresh``) drops the cache.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import string
import time
from pathlib import Path
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, field_validator

from sdl.core.models import ServiceAccount, TargetSpec
from sdl.core.module import InventoryModule, ModuleConfig, ModuleError

log = logging.getLogger("sdl.inventory.netbox")

TEMPLATE_FIELDS = frozenset({"name", "hostname", "fqdn", "account", "kind", "site", "role"})
ENDPOINTS = {
    "virtual_machines": "/api/virtualization/virtual-machines/",
    "devices": "/api/dcim/devices/",
}
GroupSource = Literal["tags", "site", "role", "cluster", "platform", "tenant"]


def _check_template(value: str) -> str:
    for _, field, spec, conversion in string.Formatter().parse(value):
        if field is None:
            continue
        if field not in TEMPLATE_FIELDS or spec or conversion:
            raise ValueError(
                f"template {value!r}: use only {{{'}, {'.join(sorted(TEMPLATE_FIELDS))}}}"
            )
    return value


class ServiceAccountDefaults(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str
    credential_path: str = Field(description="Template, e.g. 'svc/{name}/sdl-svc'.")
    credential_type: Literal["ssh_key", "password"] = "ssh_key"
    secrets: str | None = None

    @field_validator("credential_path")
    @classmethod
    def _template(cls, value: str) -> str:
        return _check_template(value)


class SystemDefaults(BaseModel):
    model_config = ConfigDict(extra="forbid")

    account: str = "root"
    port: int = Field(default=22, ge=1, le=65535)
    module: str | None = None
    secrets: str | None = None
    secret_path: str = Field(
        default="{kind}/{name}/{account}",
        description="Template for where the rolled-over credential lives in the secrets module.",
    )
    service_account: ServiceAccountDefaults | None = None
    groups: list[str] = Field(default_factory=list, description="Added to every system.")

    @field_validator("secret_path")
    @classmethod
    def _template(cls, value: str) -> str:
        return _check_template(value)


class NetBoxConfig(ModuleConfig):
    url: str = Field(description="NetBox base URL, e.g. https://netbox.example.com")
    token_env: str = Field(default="NETBOX_TOKEN", description="Env var holding the API token.")
    token_file: Path | None = Field(default=None, description="File holding the API token.")
    objects: list[Literal["virtual_machines", "devices"]] = Field(
        default=["virtual_machines"], min_length=1
    )
    filters: dict[str, str | list[str]] = Field(
        default={"status": "active"},
        description="NetBox query filters, e.g. {tag: sdl, site: ams1}.",
    )
    connect_via: Literal["primary_ip", "fqdn", "name"] = Field(
        default="primary_ip", description="Which address SDL connects to."
    )
    domain: str | None = Field(
        default=None, description="Appended to short names to form an FQDN when NetBox has none."
    )
    group_by: list[GroupSource] = Field(
        default=["tags"],
        description="NetBox attributes that become SDL groups (tags as-is, others as 'site:x').",
    )
    custom_fields: bool = Field(default=True, description="Honour the sdl_* custom fields.")
    defaults: SystemDefaults = Field(default_factory=SystemDefaults)
    cache_ttl: float = Field(default=300, ge=0)
    page_size: int = Field(default=500, ge=1, le=1000)
    ca_cert: Path | None = None
    tls_verify: bool = True
    timeout: float = 20.0


class NetBoxInventoryModule(InventoryModule):
    Config = NetBoxConfig
    description = "Reads systems (virtual machines, devices) from NetBox. Read-only."
    config: NetBoxConfig

    def __init__(self, config: Any, context: Any) -> None:
        super().__init__(config, context)
        self._client: httpx.AsyncClient | None = None
        self._transport: httpx.AsyncBaseTransport | None = None  # tests inject a mock
        self._cache: list[TargetSpec] | None = None
        self._cached_at = 0.0
        self._lock = asyncio.Lock()
        self.skipped: dict[str, str] = {}

    async def start(self) -> None:
        verify: bool | str = (
            str(self.config.ca_cert) if self.config.ca_cert else self.config.tls_verify
        )
        self._client = httpx.AsyncClient(
            base_url=self.config.url.rstrip("/"),
            verify=verify,
            timeout=self.config.timeout,
            transport=self._transport,
            headers={"Accept": "application/json"},
        )

    async def stop(self) -> None:
        if self._client is not None:
            await self._client.aclose()

    async def health(self) -> dict[str, Any]:
        try:
            response = await self._http().get("/api/status/", headers=self._auth())
        except (httpx.HTTPError, ModuleError) as exc:
            return {"ok": False, "error": str(exc)}
        info: dict[str, Any] = {"ok": response.status_code == 200}
        if response.status_code == 200:
            info["netbox_version"] = response.json().get("netbox-version")
        else:
            info["status_code"] = response.status_code
        if self.skipped:
            info["skipped"] = self.skipped
        return info

    async def refresh(self) -> None:
        self._cache = None

    async def list_systems(self) -> list[TargetSpec]:
        async with self._lock:
            fresh = time.monotonic() - self._cached_at < self.config.cache_ttl
            if self._cache is None or not fresh:
                self._cache = await self._fetch()
                self._cached_at = time.monotonic()
            return [s.model_copy(deep=True) for s in self._cache]

    # -- fetching --------------------------------------------------------------

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            raise ModuleError("netbox module has not been started")
        return self._client

    def _token(self) -> SecretStr:
        if self.config.token_file is not None:
            return SecretStr(self.config.token_file.read_text(encoding="utf-8").strip())
        token = os.environ.get(self.config.token_env)
        if not token:
            raise ModuleError(f"environment variable {self.config.token_env} is not set")
        return SecretStr(token)

    def _auth(self) -> dict[str, str]:
        token = self._token().get_secret_value()
        # NetBox 4.5+ v2 tokens (nbt_...) use Bearer; older tokens use the Token scheme.
        scheme = "Bearer" if token.startswith("nbt_") else "Token"
        return {"Authorization": f"{scheme} {token}"}

    async def _fetch(self) -> list[TargetSpec]:
        systems: list[TargetSpec] = []
        skipped: dict[str, str] = {}
        for kind in self.config.objects:
            for obj in await self._paginate(ENDPOINTS[kind]):
                label = str(obj.get("name") or f"{kind}#{obj.get('id')}")
                try:
                    systems.append(self.to_system(obj, kind))
                except (ValueError, ValidationError, KeyError) as exc:
                    skipped[label] = str(exc).splitlines()[0]
        if skipped:
            log.warning(
                "netbox %s: skipped %d object(s): %s", self.instance_id, len(skipped), skipped
            )
        self.skipped = skipped
        return systems

    async def _paginate(self, endpoint: str) -> list[dict[str, Any]]:
        query: list[tuple[str, str | int | float | bool | None]] = [
            ("limit", str(self.config.page_size))
        ]
        for key, value in self.config.filters.items():
            for item in [value] if isinstance(value, str) else value:
                query.append((key, item))
        params: list[tuple[str, str | int | float | bool | None]] | None = query
        url: str | None = endpoint
        results: list[dict[str, Any]] = []
        headers = self._auth()
        while url is not None:
            try:
                response = await self._http().get(url, params=params, headers=headers)
            except httpx.HTTPError as exc:
                raise ModuleError(f"netbox request failed: {exc}") from exc
            if response.status_code >= 400:
                raise ModuleError(f"netbox GET {endpoint}: HTTP {response.status_code}")
            body = response.json()
            results.extend(body.get("results") or [])
            next_url = body.get("next")
            # Follow only the path and query of the next page, so the token goes to the
            # configured NetBox even when NetBox (behind a proxy) names another host.
            url = self._relative(next_url) if next_url else None
            params = None  # the next URL already carries the query
        return results

    def _relative(self, url: str) -> str:
        path = httpx.URL(url).raw_path.decode("ascii")
        prefix = self._http().base_url.raw_path.decode("ascii").rstrip("/")
        if prefix and path.startswith(prefix + "/"):
            path = path[len(prefix) :]
        return path

    # -- mapping ----------------------------------------------------------------

    def to_system(self, obj: dict[str, Any], kind: str) -> TargetSpec:
        """Turn one NetBox object into an SDL system."""
        name = str(obj.get("name") or "").strip()
        if not name:
            raise ValueError("object has no name")
        hostname = name.split(".", 1)[0]
        addresses: list[str] = []
        dns_name = None
        for field in ("primary_ip4", "primary_ip6"):
            ip = obj.get(field)
            if ip:
                addresses.append(str(ipaddress.ip_interface(ip["address"]).ip))
                dns_name = dns_name or (ip.get("dns_name") or None)
        if dns_name:
            fqdn: str | None = dns_name
        elif "." in name:
            fqdn = name
        elif self.config.domain:
            fqdn = f"{name}.{self.config.domain.strip('.')}"
        else:
            fqdn = None

        if self.config.connect_via == "primary_ip":
            host = addresses[0] if addresses else ""
            if not host:
                raise ValueError("no primary IP address")
        elif self.config.connect_via == "fqdn":
            host = fqdn or ""
            if not host:
                raise ValueError("no FQDN (no DNS name on the primary IP and no domain set)")
        else:
            host = name

        custom = (obj.get("custom_fields") or {}) if self.config.custom_fields else {}
        defaults = self.config.defaults
        account = str(custom.get("sdl_account") or defaults.account)
        values = {
            "name": name,
            "hostname": hostname,
            "fqdn": fqdn or "",
            "account": account,
            "kind": "vm" if kind == "virtual_machines" else "device",
            "site": _slug(obj.get("site")),
            "role": _slug(obj.get("role")) or _slug(obj.get("device_role")),
        }

        service_account = None
        if custom.get("sdl_service_account") or defaults.service_account:
            sa = defaults.service_account
            username = custom.get("sdl_service_account") or (sa.username if sa else None)
            path = custom.get("sdl_service_account_path") or (
                sa.credential_path.format_map(values) if sa else None
            )
            if not path:
                raise ValueError("sdl_service_account is set but no credential path is known")
            service_account = ServiceAccount(
                username=str(username),
                credential_path=str(path),
                credential_type=sa.credential_type if sa else "ssh_key",
                secrets=sa.secrets if sa else None,
            )

        description = obj.get("description") or None
        return TargetSpec(
            name=name,
            hostname=hostname,
            fqdn=fqdn,
            addresses=addresses,
            host=host,
            port=int(custom.get("sdl_port") or defaults.port),
            module=custom.get("sdl_target_module") or defaults.module,
            account=account,
            secret_path=str(
                custom.get("sdl_secret_path") or defaults.secret_path.format_map(values)
            ),
            secrets=defaults.secrets,
            service_account=service_account,
            groups=sorted({*defaults.groups, *self._groups(obj)}),
            description=description,
        )

    def _groups(self, obj: dict[str, Any]) -> list[str]:
        groups: list[str] = []
        for source in self.config.group_by:
            if source == "tags":
                groups.extend(t["slug"] for t in obj.get("tags") or [] if t.get("slug"))
                continue
            value = _slug(obj.get(source))
            if source == "role" and not value:
                value = _slug(obj.get("device_role"))
            if value:
                groups.append(f"{source}:{value}")
        return groups


def _slug(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("slug") or value.get("name") or "")
    return ""
