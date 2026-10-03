"""Data models shared by the core, the modules and the API."""

from __future__ import annotations

import fnmatch
import ipaddress
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return uuid.uuid4().hex


class ActorType(StrEnum):
    USER = "user"
    SERVICE = "service"
    SYSTEM = "system"


class Access(BaseModel):
    """Which systems someone may see and act on: whole groups and individual systems.

    Roles say *what* a caller may do (run rollovers, read the log...); access
    says *on which systems*. A system is within reach when it is listed by
    name, or belongs to one of the groups, or when ``all_systems`` is set.
    """

    model_config = ConfigDict(extra="forbid")

    all_systems: bool = False
    groups: list[str] = Field(default_factory=list, description="Inventory groups.")
    systems: list[str] = Field(default_factory=list, description="Individual systems, by name.")

    def permits(self, system: TargetSpec) -> bool:
        return (
            self.all_systems
            or system.name in self.systems
            or any(g in self.groups for g in system.groups)
        )

    def union(self, other: Access) -> Access:
        return Access(
            all_systems=self.all_systems or other.all_systems,
            groups=sorted({*self.groups, *other.groups}),
            systems=sorted({*self.systems, *other.systems}),
        )


class Actor(BaseModel):
    """Who performed an action. Every audit event names one.

    ``access`` limits which systems the actor reaches; ``None`` means every
    system. It is set by the core when it authenticates a caller and is never
    written to the audit log.
    """

    type: ActorType
    id: str
    display_name: str | None = None
    roles: list[str] = Field(default_factory=list)
    access: Access | None = Field(default=None, exclude=True)

    def permits(self, system: TargetSpec) -> bool:
        return self.access is None or self.access.permits(system)

    @classmethod
    def system(cls, component: str = "orchestrator") -> Actor:
        return cls(type=ActorType.SYSTEM, id=component)


class Outcome(StrEnum):
    STARTED = "started"
    SUCCESS = "success"
    FAILURE = "failure"
    INFO = "info"
    DENIED = "denied"


class AuditEvent(BaseModel):
    """One entry in the audit log.

    `details` must never contain secret values; the audit recorder redacts
    anything that looks like one before the event reaches an audit module.
    """

    id: str = Field(default_factory=new_id)
    ts: datetime = Field(default_factory=utcnow)
    actor: Actor
    initiated_by: Actor | None = None
    action: str
    outcome: Outcome
    run_id: str | None = None
    target: str | None = None
    module: str | None = None
    message: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str | None = None
    hash: str | None = None


def action_matches(action: str, pattern: str) -> bool:
    """``rollover`` matches ``rollover`` and ``rollover.target.change``; ``*`` is a wildcard."""
    if "*" in pattern:
        return fnmatch.fnmatchcase(action, pattern)
    return action == pattern or action.startswith(pattern + ".")


class AuditQuery(BaseModel):
    """Which audit events to return. Every filter given must match; a list matches any value.

    The ``limit`` most recent matching events are returned, oldest first, or
    newest first with ``newest_first``. Narrow the date range to page back.
    """

    model_config = ConfigDict(extra="forbid")

    targets: list[str] = Field(
        default_factory=list, description="Systems (resources) the events are about."
    )
    modules: list[str] = Field(default_factory=list, description="Module instance ids.")
    actions: list[str] = Field(
        default_factory=list,
        description="Action types: 'rollover' also matches 'rollover.target.change'; "
        "'*' is a wildcard.",
    )
    outcomes: list[Outcome] = Field(default_factory=list)
    actors: list[str] = Field(
        default_factory=list,
        description="User, service or component ids; also matches events done on their behalf.",
    )
    run_id: str | None = None
    since: datetime | None = Field(default=None, description="From this time (inclusive).")
    until: datetime | None = Field(default=None, description="Up to this time (exclusive).")
    text: str | None = Field(default=None, description="Words to find in the message.")
    limit: int = Field(default=200, ge=1, le=100_000)
    newest_first: bool = False
    scope_targets: list[str] | None = Field(
        default=None,
        description="Set by the core for callers limited to some systems: only events about "
        "these systems, or done by or for ``scope_actors``, are returned.",
    )
    scope_actors: list[str] = Field(default_factory=list)

    @field_validator("since", "until")
    @classmethod
    def _aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value

    def matches(self, event: AuditEvent) -> bool:
        if self.scope_targets is not None and event.target not in self.scope_targets:
            ids = {event.actor.id, event.initiated_by.id if event.initiated_by else None}
            if not ids & set(self.scope_actors):
                return False
        if self.targets and event.target not in self.targets:
            return False
        if self.modules and event.module not in self.modules:
            return False
        if self.actions and not any(action_matches(event.action, p) for p in self.actions):
            return False
        if self.outcomes and event.outcome not in self.outcomes:
            return False
        if self.actors:
            ids = {event.actor.id, event.initiated_by.id if event.initiated_by else None}
            if not ids & set(self.actors):
                return False
        if self.run_id is not None and event.run_id != self.run_id:
            return False
        if self.since is not None and event.ts < self.since:
            return False
        if self.until is not None and event.ts >= self.until:
            return False
        if self.text:
            haystack = f"{event.action} {event.message or ''}".lower()
            if not all(word in haystack for word in self.text.lower().split()):
                return False
        return True


class AuditFacets(BaseModel):
    """The distinct values found in the audit log, with how many events carry each."""

    events: int = 0
    first: datetime | None = None
    last: datetime | None = None
    targets: dict[str, int] = Field(default_factory=dict)
    modules: dict[str, int] = Field(default_factory=dict)
    actions: dict[str, int] = Field(default_factory=dict)
    actors: dict[str, int] = Field(default_factory=dict)

    def add(self, event: AuditEvent) -> None:
        self.events += 1
        if self.first is None or event.ts < self.first:
            self.first = event.ts
        if self.last is None or event.ts > self.last:
            self.last = event.ts
        for counts, value in (
            (self.targets, event.target),
            (self.modules, event.module),
            (self.actions, event.action),
            (self.actors, event.actor.id),
        ):
            if value is not None:
                counts[value] = counts.get(value, 0) + 1
        if event.initiated_by is not None and event.initiated_by.id != event.actor.id:
            self.actors.setdefault(event.initiated_by.id, 0)


class ServiceAccount(BaseModel):
    """The account SDL signs in to a system with to perform the rollover.

    Only a reference is kept here: the credential itself (an SSH private key or
    a password) lives in a secrets module, at ``credential_path``.
    """

    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1)
    credential_path: str = Field(
        min_length=1, description="Where the account's credential lives in the secrets module."
    )
    credential_type: Literal["ssh_key", "password"] = "ssh_key"
    secrets: str | None = Field(
        default=None, description="Secrets module instance id; defaults to the only one configured."
    )


class ServiceCredential(BaseModel):
    """A service account with its credential, as handed to a target module for one session."""

    username: str
    credential_type: Literal["ssh_key", "password"]
    secret: SecretStr


class TargetSpec(BaseModel):
    """A system whose credential SDL rolls over (for example, root on a Linux VM).

    Systems come from inventory modules (and from ``targets:`` in sdl.yaml).
    ``host`` is the address SDL connects to; when it is not given it is taken
    from the FQDN, then the first IP address, then the hostname.
    """

    name: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    hostname: str | None = None
    fqdn: str | None = None
    addresses: list[str] = Field(default_factory=list, description="IP addresses.")
    host: str = Field(default="", description="Address to connect to; derived when empty.")
    port: int = Field(default=22, ge=1, le=65535)
    module: str | None = Field(
        default=None,
        description="Instance id of the target module that manages this system; "
        "defaults to the only one configured.",
    )
    account: str = "root"
    secret_path: str = Field(
        min_length=1, description="Where the credential lives in the secrets module."
    )
    secrets: str | None = Field(
        default=None, description="Secrets module instance id; defaults to the only one configured."
    )
    service_account: ServiceAccount | None = Field(
        default=None,
        description="Account SDL signs in with; defaults to the target module's own settings.",
    )
    groups: list[str] = Field(default_factory=list)
    description: str | None = None
    options: dict[str, Any] = Field(default_factory=dict)
    source: str | None = Field(
        default=None, description="Inventory the system came from; set by SDL."
    )

    @field_validator("addresses")
    @classmethod
    def _valid_addresses(cls, value: list[str]) -> list[str]:
        return [str(ipaddress.ip_address(a.strip())) for a in value]

    @model_validator(mode="after")
    def _derive_host(self) -> TargetSpec:
        if not self.host:
            host = self.fqdn or (self.addresses[0] if self.addresses else None) or self.hostname
            if not host:
                raise ValueError("a system needs a host, an FQDN, an IP address or a hostname")
            self.host = host
        return self


class InventorySource(BaseModel):
    """One inventory as seen by the core: where systems came from and whether it answered."""

    id: str
    type: str
    writable: bool = False
    ok: bool = True
    error: str | None = None
    systems: int = 0
    skipped: list[str] = Field(
        default_factory=list,
        description="Systems not listed because an earlier inventory has the same name.",
    )


class Inventory(BaseModel):
    """Every system SDL knows, merged from all inventories."""

    systems: list[TargetSpec] = Field(default_factory=list)
    sources: list[InventorySource] = Field(default_factory=list)


class SecretRecord(BaseModel):
    """A credential as stored in a secrets module."""

    value: SecretStr
    attributes: dict[str, Any] = Field(default_factory=dict)
    version: str | None = None


class StepResult(BaseModel):
    name: str
    outcome: Outcome
    message: str | None = None
    ts: datetime = Field(default_factory=utcnow)


class TargetStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    """New credential is set on the target, verified and stored in the secrets module."""
    CHECKED = "checked"
    """Dry run: every pre-flight check passed, nothing was changed."""
    FAILED = "failed"
    """Failed before the credential was changed; the target still has its old credential."""
    ROLLED_BACK = "rolled_back"
    """New credential failed verification and the previous credential was restored."""
    NEEDS_ATTENTION = "needs_attention"
    """The target's credential may have changed but SDL could not finish; see the message."""


class TargetResult(BaseModel):
    target: str
    host: str
    account: str
    source: str | None = None
    status: TargetStatus = TargetStatus.PENDING
    message: str | None = None
    secret_path: str
    secret_version: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    steps: list[StepResult] = Field(default_factory=list)


class RunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"


class RolloverRequest(BaseModel):
    targets: list[str] = Field(default_factory=list, description="Target names to roll over.")
    groups: list[str] = Field(
        default_factory=list, description="Roll over every target in these groups."
    )
    all: bool = Field(default=False, description="Roll over every configured target.")
    reason: str = Field(min_length=1, max_length=500, description="Why; recorded in the audit log.")
    dry_run: bool = Field(default=False, description="Run pre-flight checks only; change nothing.")


class RolloverRun(BaseModel):
    id: str = Field(default_factory=new_id)
    status: RunStatus = RunStatus.PENDING
    requested_by: Actor
    reason: str
    dry_run: bool = False
    created_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    results: list[TargetResult] = Field(default_factory=list)

    @property
    def done(self) -> bool:
        return self.status not in (RunStatus.PENDING, RunStatus.RUNNING)


# -- users -----------------------------------------------------------------------

USER_NAME_PATTERN = r"^[a-z0-9][a-z0-9_.@+#-]*$"
LOCAL_SOURCE = "local"
"""``UserRecord.source`` of users whose password SDL itself checks."""


class UserRecord(BaseModel):
    """A user as kept by the user-store module.

    Local users (``source == "local"``) sign in with a password SDL checks and,
    optionally, a TOTP code. Users from an identity provider (Active Directory,
    Entra ID, ...) carry that provider's instance id as ``source``; SDL keeps a
    record of them so administrators can see them, disable them, and assign
    them extra roles, groups and systems on top of what the provider's groups map to.

    Names are lower case: ``Alice`` and ``alice`` are the same user.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255, pattern=USER_NAME_PATTERN)
    display_name: str | None = Field(default=None, max_length=255)
    email: str | None = Field(default=None, max_length=255)
    source: str = LOCAL_SOURCE
    enabled: bool = True
    roles: list[str] = Field(default_factory=list)
    access: Access = Field(default_factory=Access)
    password_hash: str | None = None
    must_change_password: bool = False
    totp_secret: SecretStr | None = None
    external_groups: list[str] = Field(
        default_factory=list, description="Groups the identity provider reported at last sign-in."
    )
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    password_changed_at: datetime | None = None
    last_login: datetime | None = None

    @field_validator("name", mode="before")
    @classmethod
    def _lower(cls, value: Any) -> Any:
        return value.strip().lower() if isinstance(value, str) else value

    @property
    def local(self) -> bool:
        return self.source == LOCAL_SOURCE

    @property
    def mfa(self) -> bool:
        return self.totp_secret is not None


class UserView(BaseModel):
    """A user as the API shows it: no password hash, no TOTP secret."""

    name: str
    display_name: str | None
    email: str | None
    source: str
    enabled: bool
    roles: list[str]
    access: Access
    has_password: bool
    must_change_password: bool
    mfa: bool
    external_groups: list[str]
    created_at: datetime
    updated_at: datetime
    password_changed_at: datetime | None
    last_login: datetime | None

    @classmethod
    def of(cls, user: UserRecord) -> UserView:
        return cls(
            **user.model_dump(exclude={"password_hash", "totp_secret"}),
            has_password=user.password_hash is not None,
            mfa=user.mfa,
        )


class ExternalIdentity(BaseModel):
    """Who an identity provider says a user is, and the provider groups they belong to."""

    username: str
    display_name: str | None = None
    email: str | None = None
    groups: list[str] = Field(default_factory=list)

    @field_validator("username")
    @classmethod
    def _lower(cls, value: str) -> str:
        return value.strip().lower()


class GroupMapping(BaseModel):
    """What membership of one identity-provider group grants in SDL."""

    model_config = ConfigDict(extra="forbid")

    group: str = Field(
        min_length=1,
        description="Provider group: a name, a DN (LDAP) or an object id (Entra ID). "
        "Compared without regard to case.",
    )
    roles: list[str] = Field(default_factory=list)
    all_systems: bool = False
    groups: list[str] = Field(default_factory=list, description="SDL inventory groups.")
    systems: list[str] = Field(default_factory=list, description="Individual SDL systems.")

    @property
    def access(self) -> Access:
        return Access(all_systems=self.all_systems, groups=self.groups, systems=self.systems)
