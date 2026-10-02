"""Data models shared by the core, the modules and the API."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, SecretStr


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return uuid.uuid4().hex


class ActorType(StrEnum):
    USER = "user"
    SERVICE = "service"
    SYSTEM = "system"


class Actor(BaseModel):
    """Who performed an action. Every audit event names one."""

    type: ActorType
    id: str
    display_name: str | None = None
    roles: list[str] = Field(default_factory=list)

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


class TargetSpec(BaseModel):
    """A system whose credential SDL rolls over (for example, root on a Linux VM)."""

    name: str
    host: str
    port: int = 22
    module: str = Field(description="Instance id of the target module that manages this target.")
    account: str = "root"
    secret_path: str = Field(description="Where the credential lives in the secrets module.")
    secrets: str | None = Field(
        default=None, description="Secrets module instance id; defaults to the only one configured."
    )
    groups: list[str] = Field(default_factory=list)
    options: dict[str, Any] = Field(default_factory=dict)


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
