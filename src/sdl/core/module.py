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
    ExternalIdentity,
    GroupMapping,
    SecretRecord,
    ServiceCredential,
    TargetSpec,
    UserRecord,
)

if TYPE_CHECKING:
    from fastapi import APIRouter, Request

    from sdl.core.audit import AuditRecorder


class ModuleKind(StrEnum):
    AUDIT = "audit"
    AUTH = "auth"
    FORWARDER = "forwarder"
    GENERATOR = "generator"
    IDP = "idp"
    INVENTORY = "inventory"
    SECRETS = "secrets"
    TARGET = "target"
    USERS = "users"


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

    async def facets(self, query: AuditQuery | None = None) -> AuditFacets:
        """Summarise the events ``query`` matches (all by default, ignoring its limit):
        which systems, modules, actions and actors appear in them."""
        facets = AuditFacets()
        scan = (query or AuditQuery()).model_copy(update={"limit": 100_000})
        for event in await self.query(scan):
            facets.add(event)
        return facets

    async def verify(self) -> tuple[bool, str]:
        """Check the log has not been tampered with, if the module can tell."""
        return True, "integrity checking not supported by this module"


class AuthModule(Module):
    """Turns an API request's own credentials (an API token...) into an Actor.

    This is for machine clients. People sign in through the core's login
    endpoints instead: as the superuser, as a user of the user-store module,
    or through an identity-provider module. An Actor whose ``access`` is left
    as ``None`` reaches every system.
    """

    kind = ModuleKind.AUTH

    @abstractmethod
    async def authenticate(self, request: Request) -> Actor | None:
        """Return the caller, or None when the request carries no valid credentials."""


class UserStoreModule(Module):
    """Keeps SDL's users: local accounts and the records of identity-provider users.

    The core does all the checking (password hashes, TOTP, roles, access); a
    user store only keeps records. The superuser is never kept here: it lives
    in its own file (see ``sdl superuser set``).
    """

    kind = ModuleKind.USERS

    @abstractmethod
    async def list_users(self) -> list[UserRecord]: ...

    @abstractmethod
    async def get_user(self, name: str) -> UserRecord | None:
        """Return the user with this (lower-case) name, or None."""

    @abstractmethod
    async def put_user(self, user: UserRecord) -> None:
        """Add the user, or replace the one with the same name."""

    @abstractmethod
    async def delete_user(self, name: str) -> bool:
        """Remove the user; return False when there is none with that name."""


class IdpConfig(ModuleConfig):
    """Settings every identity provider has: how its users map onto SDL access."""

    display_name: str | None = Field(
        default=None, description="Shown on the sign-in page; defaults to the instance id."
    )
    group_mapping: list[GroupMapping] = Field(
        default_factory=list,
        description="Roles, inventory groups and systems granted per provider group.",
    )
    default_roles: list[str] = Field(
        default_factory=list, description="Roles every user of this provider gets."
    )
    provision: bool = Field(
        default=True,
        description="Keep a record of each user in the user store on first sign-in, so "
        "administrators can disable them or assign them more.",
    )
    require_totp: bool = Field(
        default=False,
        description="Password providers only: also ask for an SDL TOTP code once the user "
        "has enrolled one.",
    )


class SsoStart(BaseModel):
    """Where to send the browser to sign in, and what to remember until it comes back."""

    url: str
    state: dict[str, Any] = Field(default_factory=dict)


class IdentityProviderModule(Module):
    """An external user directory or single sign-on service: LDAP / Active Directory,
    OpenID Connect (Entra ID, Okta, Keycloak, Google...), SAML.

    ``login`` says how users sign in:

    * ``"password"``: SDL's sign-in form collects a user name and password and
      ``authenticate`` checks them with the provider (LDAP bind);
    * ``"redirect"``: the browser is sent to the provider (``begin``), which
      sends it back to SDL's callback, where ``complete`` checks the answer.

    A provider only says who the user is and which provider groups they are
    in; the core maps groups to SDL roles and access (``group_mapping``).
    """

    kind = ModuleKind.IDP
    Config: ClassVar[type[ModuleConfig]] = IdpConfig
    config: IdpConfig
    login: ClassVar[str] = "password"
    can_search: ClassVar[bool] = False

    @property
    def display_name(self) -> str:
        return self.config.display_name or self.instance_id

    async def authenticate(self, username: str, password: str) -> ExternalIdentity | None:
        """Password providers: return the user, or None when the credentials are wrong."""
        raise ModuleError(f"{self.instance_id!r} does not sign users in with a password")

    async def begin(self, callback_url: str, state: str) -> SsoStart:
        """Redirect providers: build the provider's sign-in URL.

        The provider must hand ``state`` back to the callback (``state`` or ``RelayState``).
        """
        raise ModuleError(f"{self.instance_id!r} does not sign users in by redirect")

    async def complete(
        self, params: dict[str, str], state: dict[str, Any], callback_url: str
    ) -> ExternalIdentity:
        """Redirect providers: check what the provider sent to the callback.

        ``params`` are the callback's query or form fields; ``state`` is what
        ``begin`` returned. Raise ``ModuleError`` when sign-in failed.
        """
        raise ModuleError(f"{self.instance_id!r} does not sign users in by redirect")

    async def search_users(self, query: str, limit: int = 50) -> list[ExternalIdentity]:
        """Look users up in the directory (``can_search`` providers), to add them to SDL."""
        raise ModuleError(f"{self.instance_id!r} cannot list its users")

    def metadata(self, callback_url: str) -> str | None:
        """Service-provider metadata to give the provider (SAML), if it has any."""
        return None


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
