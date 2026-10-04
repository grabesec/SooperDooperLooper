"""The audit recorder: the single path every audit event takes.

It redacts secrets, fans each event out to every configured audit module,
mirrors it to the Python log and queues it for every forwarder module. If no
audit module accepts an event the recorder raises, so a workflow never carries
on with an action it could not record. Forwarding happens afterwards, in the
background, and can never make recording fail.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from pydantic import SecretBytes, SecretStr

from sdl.core.forwarding import Forwarding
from sdl.core.models import Actor, AuditEvent, Outcome

if TYPE_CHECKING:
    from sdl.core.module import AuditModule

log = logging.getLogger("sdl.audit")

REDACTED = "[redacted]"
_SENSITIVE_KEY = re.compile(r"pass(word|phrase)?|secret|token|credential|private_?key", re.I)
# Keys that name or describe a secret without containing it, e.g. ``secret_path``.
_SAFE_SUFFIXES = ("_path", "_env", "_version", "_id", "_length", "_type")


class AuditUnavailableError(RuntimeError):
    pass


def redact(value: Any, key: str | None = None) -> Any:
    """Return a copy of ``value`` with anything secret-looking replaced."""
    if isinstance(value, SecretStr | SecretBytes):
        return REDACTED
    if key is not None and _SENSITIVE_KEY.search(key) and not key.endswith(_SAFE_SUFFIXES):
        return REDACTED
    if isinstance(value, dict):
        return {k: redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [redact(v) for v in value]
    return value


_SECRET_IN_TEXT = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization)(\s*[=:]\s*)(?:bearer\s+)?\S+"
)


def redact_text(text: str | None) -> str | None:
    """Mask ``password=...``-style secrets in free text."""
    if not text:
        return text
    return _SECRET_IN_TEXT.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)


class AuditRecorder:
    def __init__(self, modules: Sequence[AuditModule] = ()) -> None:
        self._modules: list[AuditModule] = list(modules)
        self.forwarding = Forwarding()

    def attach(self, modules: Sequence[AuditModule]) -> None:
        self._modules = list(modules)

    @property
    def primary(self) -> AuditModule:
        if not self._modules:
            raise AuditUnavailableError("no audit module is configured")
        return self._modules[0]

    async def record(
        self,
        action: str,
        outcome: Outcome,
        *,
        actor: Actor | None = None,
        initiated_by: Actor | None = None,
        run_id: str | None = None,
        target: str | None = None,
        module: str | None = None,
        message: str | None = None,
        **details: Any,
    ) -> AuditEvent:
        event = AuditEvent(
            actor=actor or Actor.system(),
            initiated_by=initiated_by,
            action=action,
            outcome=outcome,
            run_id=run_id,
            target=target,
            module=module,
            message=redact_text(message),
            details=redact(details),
        )
        if not self._modules:
            raise AuditUnavailableError("no audit module is configured")
        stored: AuditEvent | None = None
        errors: list[str] = []
        for audit_module in self._modules:
            try:
                written = await audit_module.write(event.model_copy(deep=True))
                stored = stored or written
            except Exception as exc:
                errors.append(f"{audit_module.instance_id}: {exc}")
                log.exception("audit module %s failed to write an event", audit_module.instance_id)
        if stored is None:
            raise AuditUnavailableError("; ".join(errors))
        log.info(
            "%s %s actor=%s:%s run=%s target=%s %s",
            event.action,
            event.outcome.value,
            event.actor.type.value,
            event.actor.id,
            event.run_id or "-",
            event.target or "-",
            event.message or "",
        )
        self.forwarding.publish(stored)
        return stored
