"""The module contract.

SDL's core is an orchestrator: it loads modules, wires them together and runs
workflows across them. Everything else (where the audit log goes, how users
sign in, which secret manager holds credentials, how a credential is changed
on a given kind of system) is a module.

A module is a class that subclasses one of the kind-specific contracts below
and is registered under the ``sdl.modules`` entry-point group, so third-party
packages can ship modules without touching SDL itself::

    [project.entry-points."sdl.modules"]
    "target.my_appliance" = "my_package.module:MyApplianceTarget"

Each module declares a pydantic ``Config`` model. The core validates the
module's section of ``sdl.yaml`` against it before the module is created.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import StrEnum
from typing import TYPE_CHECKING, Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from sdl.core.models import (
    Actor,
    AuditEvent,
    AuditFacets,
    AuditQuery,
    SecretRecord,
    ServiceCredential,
    TargetSpec,
)

if TYPE_CHECKING:
    from fastapi import APIRouter, Request

    from sdl.core.audit import AuditRecorder


class ModuleKind(StrEnum):
    AUDIT = "audit"
    AUTH = "auth"
    FORWARDER = "forwarder"
    GENERATOR = "generator"
    INVENTORY = "inventory"
    SECRETS = "secrets"
    TARGET = "target"


class ModuleConfig(BaseModel):
    """Base class for module configuration. Unknown keys are rejected."""

    model_config = ConfigDict(extra="forbid")


class ModuleContext:
    """What the core hands each module: its identity and the audit recorder."""

    def __init__(self, instance_id: str, audit: AuditRecorder) -> None:
        self.instance_id = instance_id
        self.audit = audit


class Module(ABC):
    """Base class for every module."""

    kind: ClassVar[ModuleKind]
    Config: ClassVar[type[ModuleConfig]] = ModuleConfig
    description: ClassVar[str] = ""

    def __init__(self, config: ModuleConfig, context: ModuleContext) -> None:
        self.config = config
        self.context = context

    @property
    def instance_id(self) -> str:
        return self.context.instance_id

    async def start(self) -> None:
        """Called once when SDL starts, after every module has been created."""

    async def stop(self) -> None:
        """Called once when SDL shuts down."""

    async def health(self) -> dict[str, Any]:
        return {"ok": True}

    def router(self) -> APIRouter | None:
        """Optional extra API routes, mounted at /api/v1/modules/<instance id>."""
        return None


class AuditModule(Module):
    """Persists audit events. Several can be configured; every one receives every event."""

    kind = ModuleKind.AUDIT

    @abstractmethod
    async def write(self, event: AuditEvent) -> AuditEvent:
        """Persist the event and return it as stored (for example, with its hash filled in)."""

    @abstractmethod
    async def query(self, query: AuditQuery) -> list[AuditEvent]:
        """Return the ``query.limit`` most recent events ``query.matches``.

        Oldest first, or newest first when ``query.newest_first`` is set.
        """

    async def facets(self) -> AuditFacets:
        """Summarise the log: which systems, modules, actions and actors appear in it."""
        facets = AuditFacets()
        for event in await self.query(AuditQuery(limit=100_000)):
            facets.add(event)
        return facets

    async def verify(self) -> tuple[bool, str]:
        """Check the log has not been tampered with, if the module can tell."""
        return True, "integrity checking not supported by this module"


class AuthModule(Module):
    """Turns an API request into an Actor. IAM providers (OIDC, Entra ID, ...) plug in here."""

    kind = ModuleKind.AUTH

    @abstractmethod
    async def authenticate(self, request: Request) -> Actor | None:
        """Return the caller, or None when the request carries no valid credentials."""


class ForwarderConfig(ModuleConfig):
    """Settings every forwarder has; the core uses them to queue and deliver events."""

    actions: list[str] = Field(
        default_factory=list,
        description="Only forward these action types ('rollover', 'api.*', ...); default all.",
    )
    exclude_actions: list[str] = Field(
        default_factory=list, description="Never forward these action types."
    )
    queue_size: int = Field(
        default=10_000,
        ge=1,
        description="Events held while the destination is unreachable; the oldest are "
        "dropped beyond this (they stay in the local audit log).",
    )
    batch_size: int = Field(default=100, ge=1, le=10_000)
    retry_max_delay: float = Field(
        default=60, gt=0, description="Longest wait, in seconds, between delivery attempts."
    )
    flush_timeout: float = Field(
        default=5, ge=0, description="Seconds to keep delivering queued events on shutdown."
    )


class ForwarderModule(Module):
    """Ships audit events to another system: syslog, Graylog, Splunk, a SIEM...

    The core queues every stored event for every forwarder and calls ``send``
    from a background task, in batches, retrying with back-off when it raises.
    A forwarder never slows down or breaks the local audit log: when the
    destination is down, events wait in the queue (up to ``queue_size``).
    """

    kind = ModuleKind.FORWARDER
    Config: ClassVar[type[ModuleConfig]] = ForwarderConfig
    config: ForwarderConfig

    @abstractmethod
    async def send(self, events: list[AuditEvent]) -> None:
        """Deliver the events, in order. Raise to have the whole batch retried later."""


class GeneratorModule(Module):
    """Produces new credential values."""

    kind = ModuleKind.GENERATOR

    @abstractmethod
    def generate(self, target: TargetSpec) -> SecretStr: ...


class InventoryModule(Module):
    """A source of systems to roll over: SDL's own store, NetBox, a CMDB, ...

    The core merges every inventory module's systems into one list. A system's
    name must be unique across inventories; when two inventories hold the same
    name, the one configured first wins and the other is reported as skipped.
    Read-only sources keep ``writable = False``; writable ones also implement
    ``put_system`` and ``delete_system``.
    """

    kind = ModuleKind.INVENTORY
    writable: ClassVar[bool] = False

    @abstractmethod
    async def list_systems(self) -> list[TargetSpec]:
        """Return every system this inventory holds."""

    async def refresh(self) -> None:
        """Drop any cached data so the next ``list_systems`` reads the source again."""

    async def put_system(self, system: TargetSpec) -> None:
        """Add the system, or replace the one with the same name."""
        raise ModuleError(f"inventory {self.instance_id!r} is read-only")

    async def delete_system(self, name: str) -> bool:
        """Remove the system; return False when there is none with that name."""
        raise ModuleError(f"inventory {self.instance_id!r} is read-only")


class SecretsModule(Module):
    """A connector to a secret manager (HashiCorp Vault, Bitwarden, ...)."""

    kind = ModuleKind.SECRETS

    @abstractmethod
    async def read(self, path: str) -> SecretRecord | None: ...

    @abstractmethod
    async def write(self, path: str, record: SecretRecord) -> str | None:
        """Store the record and return the new version identifier, if the backend has one."""

    @abstractmethod
    async def delete(self, path: str) -> None: ...


class TargetSession(ABC):
    """An open connection to one target, used for a single rollover."""

    @abstractmethod
    async def preflight(self) -> list[str]:
        """Check the rollover can be performed. Returns human-readable notes; raises on failure."""

    @abstractmethod
    async def set_credential(self, value: SecretStr) -> None: ...

    @abstractmethod
    async def verify_credential(self, value: SecretStr) -> bool:
        """Return True when the target accepts ``value`` as the account's credential."""

    async def close(self) -> None:
        return None

    async def __aenter__(self) -> TargetSession:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()


class TargetModule(Module):
    """Knows how to change and test a credential on one kind of system."""

    kind = ModuleKind.TARGET

    @abstractmethod
    async def open_session(
        self, target: TargetSpec, credential: ServiceCredential | None = None
    ) -> TargetSession:
        """Connect to the target.

        ``credential`` is the system's service account, read from the secrets
        module, when the system names one; otherwise the module signs in with
        its own configured account.
        """


class ModuleError(Exception):
    """Raised by modules for expected, reportable failures. The message is shown to users."""
