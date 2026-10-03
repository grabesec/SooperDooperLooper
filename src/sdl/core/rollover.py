"""The credential rollover workflow for a single target.

The order of steps is chosen so a credential is never lost:

1. read the system's service account credential from the secrets module, if
   the system names one, then connect and run pre-flight checks (nothing
   changed yet)
2. read the current credential from the secrets module (used for rollback)
3. generate the new credential and escrow it at a staging path in the
   secrets module *before* touching the target
4. set the new credential on the target
5. verify the target accepts the new credential; on failure, restore the
   previous one and verify that instead
6. store the new credential at the target's secret path, then remove the
   staging copy

Every step is written to the audit log (never the credential itself) and
appended to the target's result, which is what the sysadmin sees.
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic import SecretStr

from sdl.core.audit import AuditRecorder
from sdl.core.models import (
    Actor,
    Outcome,
    RolloverRun,
    SecretRecord,
    ServiceCredential,
    StepResult,
    TargetResult,
    TargetSpec,
    TargetStatus,
    utcnow,
)
from sdl.core.module import GeneratorModule, SecretsModule, TargetModule, TargetSession

log = logging.getLogger("sdl.rollover")


def _describe(exc: BaseException) -> str:
    return str(exc) or type(exc).__name__


class _Rollover:
    def __init__(
        self,
        *,
        run: RolloverRun,
        target: TargetSpec,
        result: TargetResult,
        target_module: TargetModule,
        secrets: SecretsModule,
        service_secrets: SecretsModule | None,
        generator: GeneratorModule,
        audit: AuditRecorder,
        staging_suffix: str,
    ) -> None:
        self.run = run
        self.service_secrets = service_secrets
        self.target = target
        self.result = result
        self.target_module = target_module
        self.secrets = secrets
        self.generator = generator
        self.audit = audit
        self.staging_path = f"{target.secret_path}/{staging_suffix}"
        self.actor = Actor.system()

    async def step(
        self, name: str, outcome: Outcome, message: str | None = None, **details: Any
    ) -> None:
        self.result.steps.append(StepResult(name=name, outcome=outcome, message=message))
        await self.audit.record(
            f"rollover.target.{name}",
            outcome,
            actor=self.actor,
            initiated_by=self.run.requested_by,
            run_id=self.run.id,
            target=self.target.name,
            module=self.target_module.instance_id,
            message=message,
            host=self.target.host,
            account=self.target.account,
            **details,
        )

    async def finish(self, status: TargetStatus, message: str) -> None:
        self.result.status = status
        self.result.message = message
        self.result.finished_at = utcnow()
        good = status in (TargetStatus.SUCCEEDED, TargetStatus.CHECKED)
        await self.audit.record(
            "rollover.target",
            Outcome.SUCCESS if good else Outcome.FAILURE,
            actor=self.actor,
            initiated_by=self.run.requested_by,
            run_id=self.run.id,
            target=self.target.name,
            module=self.target_module.instance_id,
            message=message,
            status=status.value,
            host=self.target.host,
            account=self.target.account,
            secret_path=self.target.secret_path,
            secret_version=self.result.secret_version,
        )

    async def execute(self) -> None:
        self.result.status = TargetStatus.RUNNING
        self.result.started_at = utcnow()
        await self.step("start", Outcome.STARTED, dry_run=self.run.dry_run)

        credential: ServiceCredential | None = None
        if self.target.service_account is not None:
            credential = await self._service_credential()
            if credential is None:
                return

        try:
            session = await self.target_module.open_session(self.target, credential)
        except Exception as exc:
            await self.step("connect", Outcome.FAILURE, _describe(exc))
            await self.finish(TargetStatus.FAILED, f"could not connect: {_describe(exc)}")
            return
        await self.step("connect", Outcome.SUCCESS, f"connected to {self.target.host}")

        async with session:
            await self._with_session(session)

    async def _service_credential(self) -> ServiceCredential | None:
        account = self.target.service_account
        assert account is not None and self.service_secrets is not None
        try:
            record = await self.service_secrets.read(account.credential_path)
        except Exception as exc:
            await self.step("service_account", Outcome.FAILURE, _describe(exc))
            await self.finish(
                TargetStatus.FAILED,
                f"could not read the service account credential: {_describe(exc)}",
            )
            return None
        if record is None:
            message = (
                f"no credential for service account {account.username!r} at "
                f"{account.credential_path} in {self.service_secrets.instance_id}"
            )
            await self.step("service_account", Outcome.FAILURE, message)
            await self.finish(TargetStatus.FAILED, message)
            return None
        await self.step(
            "service_account",
            Outcome.SUCCESS,
            f"signing in as {account.username}",
            credential_path=account.credential_path,
            credential_type=account.credential_type,
        )
        return ServiceCredential(
            username=account.username,
            credential_type=account.credential_type,
            secret=record.value,
        )

    async def _with_session(self, session: TargetSession) -> None:
        # Phase 1: nothing has changed yet, so any failure leaves the target as it was.
        try:
            notes = await session.preflight()
        except Exception as exc:
            await self.step("preflight", Outcome.FAILURE, _describe(exc))
            await self.finish(TargetStatus.FAILED, f"pre-flight check failed: {_describe(exc)}")
            return
        await self.step("preflight", Outcome.SUCCESS, "; ".join(notes) or None)

        try:
            previous = await self.secrets.read(self.target.secret_path)
        except Exception as exc:
            await self.step("read_previous", Outcome.FAILURE, _describe(exc))
            await self.finish(
                TargetStatus.FAILED, f"could not read the secrets module: {_describe(exc)}"
            )
            return
        await self.step(
            "read_previous",
            Outcome.SUCCESS,
            "current credential found" if previous else "no stored credential (first rollover)",
            secret_path=self.target.secret_path,
            secret_version=previous.version if previous else None,
        )

        if self.run.dry_run:
            await self.finish(TargetStatus.CHECKED, "dry run: all checks passed, nothing changed")
            return

        new_value = self.generator.generate(self.target)
        await self.step(
            "generate",
            Outcome.SUCCESS,
            f"generated by {self.generator.instance_id}",
            value_length=len(new_value.get_secret_value()),
        )

        try:
            await self.secrets.write(
                self.staging_path,
                SecretRecord(value=new_value, attributes=self._attributes("pending")),
            )
        except Exception as exc:
            await self.step("escrow", Outcome.FAILURE, _describe(exc))
            await self.finish(
                TargetStatus.FAILED,
                f"could not escrow the new credential, target not changed: {_describe(exc)}",
            )
            return
        await self.step("escrow", Outcome.SUCCESS, secret_path=self.staging_path)

        # Phase 2: the target is being changed.
        try:
            await self.step("change", Outcome.STARTED)
            await session.set_credential(new_value)
        except Exception as exc:
            await self.step("change", Outcome.FAILURE, _describe(exc))
            # The command may have applied before failing (a timeout, a dropped
            # connection), so find out which credential the target has now.
            if await self._safe_verify(session, new_value):
                await self.step("change", Outcome.INFO, "the new credential was applied anyway")
            else:
                if previous is not None and await self._safe_verify(session, previous.value):
                    await self._discard_staging()
                    await self.finish(
                        TargetStatus.FAILED,
                        f"could not change the credential, the previous one is still in place: "
                        f"{_describe(exc)}",
                    )
                else:
                    await self.finish(
                        TargetStatus.NEEDS_ATTENTION,
                        f"changing the credential failed ({_describe(exc)}) and SDL cannot tell "
                        f"which credential is in place now; the new one is escrowed at "
                        f"{self.staging_path}",
                    )
                return
        else:
            await self.step("change", Outcome.SUCCESS)

        if not await self._safe_verify(session, new_value):
            await self.step("verify", Outcome.FAILURE, "target rejected the new credential")
            await self._rollback(session, previous)
            return
        await self.step("verify", Outcome.SUCCESS, "target accepts the new credential")

        # Phase 3: the target has the new credential; record it.
        try:
            version = await self.secrets.write(
                self.target.secret_path,
                SecretRecord(value=new_value, attributes=self._attributes("active")),
            )
        except Exception as exc:
            await self.step("store", Outcome.FAILURE, _describe(exc))
            await self.finish(
                TargetStatus.NEEDS_ATTENTION,
                f"the new credential is set and verified, but storing it at "
                f"{self.target.secret_path} failed ({_describe(exc)}); it is escrowed at "
                f"{self.staging_path}",
            )
            return
        self.result.secret_version = version
        await self.step(
            "store", Outcome.SUCCESS, secret_path=self.target.secret_path, secret_version=version
        )

        await self._discard_staging()
        await self.finish(TargetStatus.SUCCEEDED, "credential rolled over and verified")

    async def _safe_verify(self, session: TargetSession, value: SecretStr) -> bool:
        try:
            return await session.verify_credential(value)
        except Exception as exc:
            await self.step("verify", Outcome.FAILURE, f"verification error: {_describe(exc)}")
            return False

    async def _rollback(self, session: TargetSession, previous: SecretRecord | None) -> None:
        if previous is None:
            await self.step("rollback", Outcome.FAILURE, "no previous credential to restore")
            await self.finish(
                TargetStatus.NEEDS_ATTENTION,
                f"the target rejected the new credential and there is no previous one to "
                f"restore; the new one is escrowed at {self.staging_path}",
            )
            return
        try:
            await session.set_credential(previous.value)
        except Exception as exc:
            await self.step("rollback", Outcome.FAILURE, _describe(exc))
            await self.finish(
                TargetStatus.NEEDS_ATTENTION,
                f"the target rejected the new credential and restoring the previous one failed "
                f"({_describe(exc)}); the new one is escrowed at {self.staging_path}",
            )
            return
        if await self._safe_verify(session, previous.value):
            await self.step(
                "rollback", Outcome.SUCCESS, "previous credential restored and verified"
            )
            await self._discard_staging()
            await self.finish(
                TargetStatus.ROLLED_BACK,
                "the target rejected the new credential; the previous one was restored",
            )
        else:
            await self.step("rollback", Outcome.FAILURE, "restored credential failed verification")
            await self.finish(
                TargetStatus.NEEDS_ATTENTION,
                f"the previous credential was re-applied but could not be verified; the new one "
                f"is escrowed at {self.staging_path}",
            )

    async def _discard_staging(self) -> None:
        try:
            await self.secrets.delete(self.staging_path)
        except Exception as exc:
            await self.step("cleanup", Outcome.FAILURE, f"could not remove staging copy: {exc}")
        else:
            await self.step("cleanup", Outcome.SUCCESS, secret_path=self.staging_path)

    def _attributes(self, state: str) -> dict[str, Any]:
        return {
            "state": state,
            "account": self.target.account,
            "host": self.target.host,
            "target": self.target.name,
            "run_id": self.run.id,
            "requested_by": self.run.requested_by.id,
            "rotated_at": utcnow().isoformat(),
        }


async def rollover_target(
    *,
    run: RolloverRun,
    target: TargetSpec,
    result: TargetResult,
    target_module: TargetModule,
    secrets: SecretsModule,
    service_secrets: SecretsModule | None,
    generator: GeneratorModule,
    audit: AuditRecorder,
    staging_suffix: str,
) -> None:
    rollover = _Rollover(
        run=run,
        target=target,
        result=result,
        target_module=target_module,
        secrets=secrets,
        service_secrets=service_secrets,
        generator=generator,
        audit=audit,
        staging_suffix=staging_suffix,
    )
    try:
        await rollover.execute()
    except Exception as exc:
        # Most likely the audit log became unavailable. Stop here rather than
        # carry on with actions that cannot be recorded.
        log.exception("rollover of %s aborted", target.name)
        changed = any(s.name == "change" for s in result.steps)
        result.status = TargetStatus.NEEDS_ATTENTION if changed else TargetStatus.FAILED
        result.message = f"aborted: {_describe(exc)}"
        if changed:
            result.message += f"; the new credential is escrowed at {rollover.staging_path}"
        result.finished_at = utcnow()
