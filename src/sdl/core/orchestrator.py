"""The orchestrator: SDL's thin core.

It creates the configured modules, hands each one the audit recorder, and
runs workflows (today: credential rollovers) that coordinate several modules.
It does no protocol or storage work of its own.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TypeVar

from sdl.core.audit import AuditRecorder
from sdl.core.models import (
    Actor,
    Inventory,
    InventorySource,
    Outcome,
    RolloverRequest,
    RolloverRun,
    RunStatus,
    TargetResult,
    TargetSpec,
    TargetStatus,
    utcnow,
)
from sdl.core.module import (
    AuditModule,
    AuthModule,
    GeneratorModule,
    InventoryModule,
    Module,
    ModuleContext,
    SecretsModule,
    TargetModule,
)
from sdl.core.registry import ModuleRegistry
from sdl.core.rollover import rollover_target
from sdl.core.settings import Settings

log = logging.getLogger("sdl.orchestrator")

M = TypeVar("M", bound=Module)


CONFIG_INVENTORY = "sdl.yaml"
"""Inventory id of the systems listed under ``targets:`` in the configuration file."""


class ConfigError(ValueError):
    pass


class RequestError(ValueError):
    """The caller asked for something that cannot be done (unknown target, busy target...)."""


class NotFoundError(RequestError):
    """The caller named a system or inventory that does not exist."""


class ConflictError(RequestError):
    """The request clashes with the current state (a busy system, a duplicate name...)."""


class Orchestrator:
    def __init__(self, settings: Settings, registry: ModuleRegistry | None = None) -> None:
        self.settings = settings
        self.registry = registry or ModuleRegistry.from_entry_points()
        self.audit = AuditRecorder()
        self.modules: dict[str, Module] = {}
        self.runs: dict[str, RolloverRun] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._busy_targets: set[str] = set()
        self._started = False

    # -- lifecycle -----------------------------------------------------------

    def load(self) -> None:
        """Create and validate the configured modules. Safe to call more than once."""
        if self.modules:
            return
        for instance_id, spec in self.settings.modules.items():
            module_cls = self.registry.resolve(spec.type)
            try:
                config = module_cls.Config.model_validate(spec.config)
            except ValueError as exc:
                raise ConfigError(f"module {instance_id!r} ({spec.type}): {exc}") from exc
            self.modules[instance_id] = module_cls(config, ModuleContext(instance_id, self.audit))

        audit_modules = self.all_of(AuditModule)
        if not audit_modules:
            raise ConfigError("at least one audit module must be configured")
        self.audit.attach(audit_modules)
        self._validate()

    async def start(self) -> None:
        self.load()
        audit_modules = self.all_of(AuditModule)
        # Audit modules first so everything after them can be recorded.
        ordered = audit_modules + [m for m in self.modules.values() if m not in audit_modules]
        for module in ordered:
            await module.start()
        self._started = True
        await self.audit.record(
            "system.start",
            Outcome.SUCCESS,
            message="SDL started",
            modules={i: type(m).__name__ for i, m in self.modules.items()},
            config_targets=len(self.settings.targets),
            inventories=[m.instance_id for m in self.all_of(InventoryModule)],
        )

    async def stop(self) -> None:
        if not self._started:
            return
        running = list(self._tasks.values())
        if running:
            # Interrupting a target mid-change could leave it in an unknown
            # state, so give running rollovers time to finish first.
            log.info("waiting for %d running rollover(s) to finish", len(running))
            _, pending = await asyncio.wait(running, timeout=self.settings.rollover.shutdown_grace)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        await self.audit.record("system.stop", Outcome.SUCCESS, message="SDL stopping")
        audit_modules = self.all_of(AuditModule)
        others = [m for m in self.modules.values() if m not in audit_modules]
        for module in [*reversed(others), *reversed(audit_modules)]:
            try:
                await module.stop()
            except Exception:
                log.exception("module %s failed to stop", module.instance_id)
        self._started = False

    def _validate(self) -> None:
        if CONFIG_INVENTORY in self.modules:
            raise ConfigError(f"{CONFIG_INVENTORY!r} is reserved and cannot be a module id")
        for target in self.settings.targets:
            problems = self.check_system(target)
            if problems:
                raise ConfigError(f"target {target.name!r}: {'; '.join(problems)}")
        if self.settings.targets or self.all_of(InventoryModule):
            self.one_of(GeneratorModule, self.settings.rollover.generator)

    # -- module lookup -------------------------------------------------------

    def all_of(self, kind: type[M]) -> list[M]:
        return [m for m in self.modules.values() if isinstance(m, kind)]

    def one_of(self, kind: type[M], instance_id: str | None = None) -> M:
        if instance_id is not None:
            module = self.modules.get(instance_id)
            if not isinstance(module, kind):
                raise ConfigError(f"{instance_id!r} is not a configured {kind.kind.value} module")
            return module
        candidates = self.all_of(kind)
        if len(candidates) != 1:
            raise ConfigError(
                f"expected exactly one {kind.kind.value} module, found {len(candidates)}; "
                "name the one to use explicitly"
            )
        return candidates[0]

    def auth_module(self) -> AuthModule:
        return self.one_of(AuthModule, self.settings.api.auth)

    def check_system(self, system: TargetSpec) -> list[str]:
        """Return what stops ``system`` from being rolled over with the configured modules."""
        problems: list[str] = []
        lookups: list[tuple[type[Module], str | None]] = [
            (TargetModule, system.module),
            (SecretsModule, system.secrets),
        ]
        if system.service_account is not None:
            lookups.append((SecretsModule, system.service_account.secrets))
        for kind, instance_id in lookups:
            try:
                self.one_of(kind, instance_id)
            except ConfigError as exc:
                problems.append(str(exc))
        return problems

    def _target_module(self, target: TargetSpec) -> TargetModule:
        try:
            return self.one_of(TargetModule, target.module)
        except ConfigError as exc:
            raise ConfigError(f"target {target.name!r}: {exc}") from exc

    def _secrets_module(self, target: TargetSpec, instance_id: str | None = None) -> SecretsModule:
        try:
            return self.one_of(SecretsModule, instance_id or target.secrets)
        except ConfigError as exc:
            raise ConfigError(f"target {target.name!r}: {exc}") from exc

    def _service_secrets(self, target: TargetSpec) -> SecretsModule | None:
        if target.service_account is None:
            return None
        return self._secrets_module(target, target.service_account.secrets)

    # -- inventory -----------------------------------------------------------

    @property
    def targets(self) -> list[TargetSpec]:
        """Systems listed under ``targets:`` in the configuration file."""
        return [t.model_copy(update={"source": CONFIG_INVENTORY}) for t in self.settings.targets]

    def inventory_module(self, instance_id: str) -> InventoryModule:
        module = self.modules.get(instance_id)
        if not isinstance(module, InventoryModule):
            raise NotFoundError(f"no inventory named {instance_id!r}")
        return module

    async def inventory(self) -> Inventory:
        """Every system from every inventory, the configuration file's first.

        An inventory that fails or times out is reported in ``sources`` and the
        others are still listed, so one unreachable NetBox does not block
        rollovers of systems kept elsewhere.
        """
        modules = self.all_of(InventoryModule)
        timeout = self.settings.inventory.timeout

        async def fetch(module: InventoryModule) -> list[TargetSpec]:
            return await asyncio.wait_for(module.list_systems(), timeout)

        fetched = await asyncio.gather(*(fetch(m) for m in modules), return_exceptions=True)
        result = Inventory()
        seen: set[str] = set()

        def merge(source: InventorySource, systems: list[TargetSpec]) -> None:
            for system in systems:
                if system.name in seen:
                    source.skipped.append(system.name)
                    continue
                seen.add(system.name)
                result.systems.append(system.model_copy(update={"source": source.id}))
                source.systems += 1
            result.sources.append(source)

        if self.settings.targets or not modules:
            merge(InventorySource(id=CONFIG_INVENTORY, type="config"), self.settings.targets)
        for module, systems in zip(modules, fetched, strict=True):
            source = InventorySource(
                id=module.instance_id,
                type=self.settings.modules[module.instance_id].type,
                writable=module.writable,
            )
            if isinstance(systems, BaseException):
                if not isinstance(systems, Exception):
                    raise systems
                source.ok = False
                source.error = (
                    f"timed out after {timeout:g}s"
                    if isinstance(systems, TimeoutError)
                    else _describe(systems)
                )
                log.warning("inventory %s is unavailable: %s", module.instance_id, source.error)
                merge(source, [])
            else:
                merge(source, systems)
        return result

    async def get_system(self, name: str) -> TargetSpec:
        inventory = await self.inventory()
        for system in inventory.systems:
            if system.name == name:
                return system
        raise NotFoundError(f"no system named {name!r}{_unavailable(inventory)}")

    async def put_system(self, inventory_id: str, system: TargetSpec, actor: Actor) -> TargetSpec:
        """Add or replace a system in a writable inventory, after checking it is usable."""
        module = self.inventory_module(inventory_id)
        if not module.writable:
            raise RequestError(f"inventory {inventory_id!r} is read-only")
        system = system.model_copy(update={"source": None})
        problems = self.check_system(system)
        if problems:
            raise RequestError(f"system {system.name!r}: {'; '.join(problems)}")
        current = await self.inventory()
        elsewhere = [s.source for s in current.systems if s.name == system.name]
        if elsewhere and elsewhere[0] != inventory_id:
            raise ConflictError(
                f"a system named {system.name!r} already comes from inventory {elsewhere[0]!r}"
            )
        if system.name in self._busy_targets:
            raise ConflictError(f"rollover in progress for {system.name!r}; try again later")
        action = "inventory.system.update" if elsewhere else "inventory.system.add"
        try:
            await module.put_system(system)
        except Exception as exc:
            await self.audit.record(
                action,
                Outcome.FAILURE,
                actor=actor,
                target=system.name,
                module=inventory_id,
                message=_describe(exc),
            )
            raise
        await self.audit.record(
            action,
            Outcome.SUCCESS,
            actor=actor,
            target=system.name,
            module=inventory_id,
            system=_audit_view(system),
        )
        return system.model_copy(update={"source": inventory_id})

    async def delete_system(self, inventory_id: str, name: str, actor: Actor) -> None:
        module = self.inventory_module(inventory_id)
        if not module.writable:
            raise RequestError(f"inventory {inventory_id!r} is read-only")
        if name in self._busy_targets:
            raise ConflictError(f"rollover in progress for {name!r}; try again later")
        if not await module.delete_system(name):
            raise NotFoundError(f"inventory {inventory_id!r} has no system named {name!r}")
        await self.audit.record(
            "inventory.system.delete",
            Outcome.SUCCESS,
            actor=actor,
            target=name,
            module=inventory_id,
        )

    async def refresh_inventory(self, actor: Actor) -> Inventory:
        for module in self.all_of(InventoryModule):
            await module.refresh()
        inventory = await self.inventory()
        await self.audit.record(
            "inventory.refresh",
            Outcome.SUCCESS,
            actor=actor,
            sources={s.id: s.systems if s.ok else s.error for s in inventory.sources},
        )
        return inventory

    async def select_targets(self, request: RolloverRequest) -> list[TargetSpec]:
        inventory = await self.inventory()
        systems = inventory.systems
        by_name = {t.name: t for t in systems}
        unknown = [name for name in request.targets if name not in by_name]
        if unknown:
            raise RequestError(f"unknown target(s): {', '.join(unknown)}{_unavailable(inventory)}")
        known_groups = {g for t in systems for g in t.groups}
        unknown_groups = [g for g in request.groups if g not in known_groups]
        if unknown_groups:
            raise RequestError(
                f"unknown group(s): {', '.join(unknown_groups)}{_unavailable(inventory)}"
            )
        selected = [
            t
            for t in systems
            if request.all or t.name in request.targets or set(t.groups) & set(request.groups)
        ]
        if not selected:
            raise RequestError("no targets selected; name targets, groups, or set all")
        problems = [f"{t.name}: {'; '.join(p)}" for t in selected if (p := self.check_system(t))]
        if problems:
            raise RequestError("cannot roll over " + " | ".join(problems))
        return selected

    # -- rollovers -----------------------------------------------------------

    async def start_rollover(self, request: RolloverRequest, actor: Actor) -> RolloverRun:
        targets = await self.select_targets(request)
        busy = [t.name for t in targets if t.name in self._busy_targets]
        if busy:
            raise ConflictError(f"rollover already in progress for: {', '.join(busy)}")
        run = RolloverRun(
            requested_by=actor,
            reason=request.reason,
            dry_run=request.dry_run,
            results=[
                TargetResult(
                    target=t.name,
                    host=t.host,
                    account=t.account,
                    source=t.source,
                    secret_path=t.secret_path,
                )
                for t in targets
            ],
        )
        self._busy_targets.update(t.name for t in targets)
        self.runs[run.id] = run
        try:
            await self.audit.record(
                "rollover.requested",
                Outcome.INFO,
                actor=actor,
                run_id=run.id,
                message=request.reason,
                targets=[t.name for t in targets],
                dry_run=request.dry_run,
            )
        except Exception:
            self._busy_targets.difference_update(t.name for t in targets)
            del self.runs[run.id]
            raise
        self._tasks[run.id] = asyncio.create_task(self._execute(run, targets), name=f"run-{run.id}")
        return run

    async def wait(self, run_id: str, timeout: float | None = None) -> RolloverRun:
        task = self._tasks.get(run_id)
        if task is not None:
            await asyncio.wait_for(asyncio.shield(task), timeout)
        return self.runs[run_id]

    async def _execute(self, run: RolloverRun, targets: list[TargetSpec]) -> None:
        run.status = RunStatus.RUNNING
        system = Actor.system()
        semaphore = asyncio.Semaphore(self.settings.rollover.max_parallel)

        async def one(target: TargetSpec, result: TargetResult) -> None:
            async with semaphore:
                try:
                    await rollover_target(
                        run=run,
                        target=target,
                        result=result,
                        target_module=self._target_module(target),
                        secrets=self._secrets_module(target),
                        service_secrets=self._service_secrets(target),
                        generator=self.one_of(GeneratorModule, self.settings.rollover.generator),
                        audit=self.audit,
                        staging_suffix=self.settings.rollover.staging_suffix,
                    )
                finally:
                    self._busy_targets.discard(target.name)

        try:
            await self.audit.record(
                "rollover.run",
                Outcome.STARTED,
                actor=system,
                initiated_by=run.requested_by,
                run_id=run.id,
                targets=len(targets),
                dry_run=run.dry_run,
            )
            await asyncio.gather(*(one(t, r) for t, r in zip(targets, run.results, strict=True)))
        except Exception as exc:
            log.exception("rollover run %s crashed", run.id)
            for result in run.results:
                if result.status == TargetStatus.PENDING:
                    result.status = TargetStatus.FAILED
                    result.message = f"run aborted before this target started: {exc}"
                elif result.status == TargetStatus.RUNNING:
                    result.status = TargetStatus.NEEDS_ATTENTION
                    result.message = f"run aborted: {exc}"
        finally:
            self._busy_targets.difference_update(t.name for t in targets)
            run.status = _summarise(run)
            run.finished_at = utcnow()
            self._tasks.pop(run.id, None)
            counts: dict[str, int] = {}
            for result in run.results:
                counts[result.status.value] = counts.get(result.status.value, 0) + 1
            try:
                await self.audit.record(
                    "rollover.run",
                    Outcome.SUCCESS if run.status == RunStatus.SUCCEEDED else Outcome.FAILURE,
                    actor=system,
                    initiated_by=run.requested_by,
                    run_id=run.id,
                    message=f"run {run.status.value}",
                    results=counts,
                )
            except Exception:
                log.exception("could not record the end of run %s", run.id)


def _describe(exc: BaseException) -> str:
    return str(exc) or type(exc).__name__


def _unavailable(inventory: Inventory) -> str:
    down = [f"{s.id} ({s.error})" for s in inventory.sources if not s.ok]
    return f"; unavailable inventories: {', '.join(down)}" if down else ""


def _audit_view(system: TargetSpec) -> dict[str, object]:
    """What the audit log records about a system: where it is and how SDL reaches it."""
    return system.model_dump(
        mode="json",
        include={
            "hostname",
            "fqdn",
            "addresses",
            "host",
            "port",
            "module",
            "account",
            "secret_path",
            "secrets",
            "service_account",
            "groups",
        },
    )


def _summarise(run: RolloverRun) -> RunStatus:
    good = {TargetStatus.SUCCEEDED, TargetStatus.CHECKED}
    statuses = {r.status for r in run.results}
    if statuses <= good:
        return RunStatus.SUCCEEDED
    if statuses & good:
        return RunStatus.PARTIAL
    return RunStatus.FAILED
