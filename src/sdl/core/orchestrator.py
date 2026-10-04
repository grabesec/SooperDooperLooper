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
from sdl.core.errors import (
    ConfigError,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    RequestError,
)
from sdl.core.identity import Identity
from sdl.core.models import (
    Access,
    Actor,
    AuditQuery,
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
    ForwarderModule,
    GeneratorModule,
    IdentityProviderModule,
    InventoryModule,
    Module,
    ModuleContext,
    SecretsModule,
    TargetModule,
    UserStoreModule,
)
from sdl.core.registry import ModuleRegistry
from sdl.core.rollover import rollover_target
from sdl.core.settings import Settings

log = logging.getLogger("sdl.orchestrator")

M = TypeVar("M", bound=Module)


CONFIG_INVENTORY = "sdl.yaml"
"""Inventory id of the systems listed under ``targets:`` in the configuration file."""


class Orchestrator:
    def __init__(self, settings: Settings, registry: ModuleRegistry | None = None) -> None:
        self.settings = settings
        self.registry = registry or ModuleRegistry.from_entry_points()
        self.audit = AuditRecorder()
        self.modules: dict[str, Module] = {}
        self.runs: dict[str, RolloverRun] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._busy_targets: set[str] = set()
        self._busy_specs: dict[str, TargetSpec] = {}
        self._inventory_down: dict[str, str] = {}
        self._started = False
        self._identity: Identity | None = None
        self._run_systems: dict[str, dict[str, list[str]]] = {}

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
        self.audit.forwarding.attach(self.all_of(ForwarderModule), self._forwarder_status)
        self._validate()
        users = self.all_of(UserStoreModule)
        if self.settings.identity.users is not None or len(users) > 1:
            users = [self.one_of(UserStoreModule, self.settings.identity.users)]
        auth_modules = self.all_of(AuthModule)
        if self.settings.api.auth is not None:
            auth_modules = [self.one_of(AuthModule, self.settings.api.auth)]
        self._identity = Identity(
            self.settings.identity,
            self.settings.api,
            self.audit,
            users[0] if users else None,
            self.all_of(IdentityProviderModule),
            auth_modules,
            {i: s.type for i, s in self.settings.modules.items()},
        )

    async def start(self) -> None:
        self.load()
        audit_modules = self.all_of(AuditModule)
        # Audit modules first so everything after them can be recorded.
        ordered = audit_modules + [m for m in self.modules.values() if m not in audit_modules]
        for module in ordered:
            try:
                await module.start()
            except Exception as exc:
                await self._record_module_failure("module.start", module, exc)
                raise
        self.audit.forwarding.start()
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
        await self.audit.forwarding.stop()
        audit_modules = self.all_of(AuditModule)
        others = [m for m in self.modules.values() if m not in audit_modules]
        for module in [*reversed(others), *reversed(audit_modules)]:
            try:
                await module.stop()
            except Exception as exc:
                log.exception("module %s failed to stop", module.instance_id)
                if module not in audit_modules:
                    await self._record_module_failure("module.stop", module, exc)
        self._started = False

    async def _record_module_failure(self, action: str, module: Module, exc: Exception) -> None:
        try:
            await self.audit.record(
                action,
                Outcome.FAILURE,
                module=module.instance_id,
                message=_describe(exc),
                type=self.settings.modules[module.instance_id].type,
            )
        except Exception:
            log.exception("could not record that module %s failed", module.instance_id)

    async def _forwarder_status(self, module: ForwarderModule, ok: bool, detail: str) -> None:
        """Record a forwarder losing or regaining its destination (not every retry)."""
        try:
            await self.audit.record(
                "forwarder.available" if ok else "forwarder.unavailable",
                Outcome.SUCCESS if ok else Outcome.FAILURE,
                module=module.instance_id,
                message=detail,
            )
        except Exception:
            log.exception("could not record the status of forwarder %s", module.instance_id)

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

    @property
    def identity(self) -> Identity:
        if self._identity is None:
            raise ConfigError("the orchestrator has not been loaded")
        return self._identity

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
        await self._record_inventory_changes(result)
        return result

    async def _record_inventory_changes(self, inventory: Inventory) -> None:
        """Record an inventory becoming unavailable, and available again, once each."""
        for source in inventory.sources:
            was_down = source.id in self._inventory_down
            if source.ok == (not was_down):
                continue
            if source.ok:
                del self._inventory_down[source.id]
            else:
                self._inventory_down[source.id] = source.error or ""
            await self.audit.record(
                "inventory.available" if source.ok else "inventory.unavailable",
                Outcome.SUCCESS if source.ok else Outcome.FAILURE,
                module=source.id,
                message=source.error,
                systems=source.systems,
            )

    async def visible_inventory(self, actor: Actor) -> Inventory:
        """The inventory as ``actor`` may see it: only the systems assigned to them."""
        inventory = await self.inventory()
        inventory.systems = [s for s in inventory.systems if actor.permits(s)]
        return inventory

    async def get_system(self, name: str, actor: Actor | None = None) -> TargetSpec:
        inventory = await self.inventory()
        for system in inventory.systems:
            if system.name == name and (actor is None or actor.permits(system)):
                return system
        raise NotFoundError(f"no system named {name!r}{_unavailable(inventory)}")

    async def audit_scope(self, actor: Actor, query: AuditQuery) -> AuditQuery:
        """Limit an audit query to what ``actor`` may see: events about their systems, and
        their own actions."""
        if actor.access is None or actor.access.all_systems:
            return query
        systems = (await self.visible_inventory(actor)).systems
        return query.model_copy(
            update={"scope_targets": [s.name for s in systems], "scope_actors": [actor.id]}
        )

    def visible_runs(self, actor: Actor) -> list[RolloverRun]:
        """Rollover runs, newest first, showing ``actor`` only the systems assigned to them."""
        runs = sorted(self.runs.values(), key=lambda r: r.created_at, reverse=True)
        return [v for v in (self.visible_run(r, actor) for r in runs) if v is not None]

    def visible_run(self, run: RolloverRun, actor: Actor) -> RolloverRun | None:
        if actor.access is None or actor.access.all_systems:
            return run
        allowed = {
            name
            for name, groups in self._run_systems.get(run.id, {}).items()
            if _permits(actor.access, name, groups)
        }
        results = [r for r in run.results if r.target in allowed]
        if not results and run.requested_by.id != actor.id:
            return None
        return run.model_copy(update={"results": results})

    def _path_clashes(self, systems: list[TargetSpec]) -> list[str]:
        """Find systems whose secret paths collide with another system's paths."""
        suffix = self.settings.rollover.staging_suffix
        owners: dict[str, str] = {}
        problems: list[str] = []
        for s in systems:
            if s.secret_path in owners and owners[s.secret_path] != s.name:
                problems.append(
                    f"system {s.name!r} has the same secret_path as {owners[s.secret_path]!r}"
                )
            owners.setdefault(s.secret_path, s.name)
        for s in systems:
            if s.service_account is None:
                continue
            path = s.service_account.credential_path
            for other in systems:
                if other.name != s.name and path in (
                    other.secret_path,
                    f"{other.secret_path}/{suffix}",
                ):
                    problems.append(
                        f"system {s.name!r} service account credential_path is the "
                        f"secret_path of {other.name!r}"
                    )
        return problems

    async def put_system(self, inventory_id: str, system: TargetSpec, actor: Actor) -> TargetSpec:
        """Add or replace a system in a writable inventory, after checking it is usable."""
        module = self.inventory_module(inventory_id)
        if not module.writable:
            raise RequestError(f"inventory {inventory_id!r} is read-only")
        system = system.model_copy(update={"source": None})
        problems = self.check_system(system)
        if problems:
            raise RequestError(f"system {system.name!r}: {'; '.join(problems)}")
        if not actor.permits(system):
            raise ForbiddenError(
                f"system {system.name!r} would be outside the groups and systems assigned to you"
            )
        current = await self.inventory()
        existing = [s for s in current.systems if s.name == system.name]
        if existing and not actor.permits(existing[0]):
            raise ForbiddenError(
                f"system {system.name!r} would be outside the groups and systems assigned to you"
            )
        clashes = self._path_clashes(
            [system, *(s for s in current.systems if s.name != system.name)]
        )
        if clashes:
            raise RequestError("; ".join(clashes))
        elsewhere = [s.source for s in existing]
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
        if actor.access is not None:
            current = [s for s in (await module.list_systems()) if s.name == name]
            if current and not actor.permits(current[0]):
                raise NotFoundError(f"inventory {inventory_id!r} has no system named {name!r}")
        if name in self._busy_targets:
            raise ConflictError(f"rollover in progress for {name!r}; try again later")
        try:
            deleted = await module.delete_system(name)
        except Exception as exc:
            await self.audit.record(
                "inventory.system.delete",
                Outcome.FAILURE,
                actor=actor,
                target=name,
                module=inventory_id,
                message=_describe(exc),
            )
            raise
        if not deleted:
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
            try:
                await module.refresh()
            except Exception as exc:
                await self.audit.record(
                    "inventory.refresh",
                    Outcome.FAILURE,
                    actor=actor,
                    module=module.instance_id,
                    message=_describe(exc),
                )
                raise
        inventory = await self.inventory()
        await self.audit.record(
            "inventory.refresh",
            Outcome.SUCCESS,
            actor=actor,
            sources={s.id: s.systems if s.ok else s.error for s in inventory.sources},
        )
        return inventory

    async def select_targets(
        self, request: RolloverRequest, actor: Actor | None = None
    ) -> list[TargetSpec]:
        """The systems a rollover request names, among those ``actor`` may reach.

        Systems outside the caller's assignments are reported as unknown, so
        their names are not revealed.
        """
        inventory = await self.inventory()
        systems = [s for s in inventory.systems if actor is None or actor.permits(s)]
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
        targets = await self.select_targets(request, actor)
        clashes = self._path_clashes((await self.inventory()).systems)
        clashes = [c for c in clashes if any(repr(t.name) in c for t in targets)]
        if clashes:
            raise RequestError("cannot roll over: " + "; ".join(clashes))
        running = [spec for name, spec in self._busy_specs.items() if name in self._busy_targets]
        busy = [
            t.name
            for t in targets
            if t.name in self._busy_targets
            or any(
                t.secret_path == r.secret_path
                or (t.host, t.port, t.account) == (r.host, r.port, r.account)
                for r in running
            )
        ]
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
        self._busy_specs.update((t.name, t) for t in targets)
        self.runs[run.id] = run
        self._run_systems[run.id] = {t.name: list(t.groups) for t in targets}
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
            del self._run_systems[run.id]
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


def _permits(access: Access, name: str, groups: list[str]) -> bool:
    return access.all_systems or name in access.systems or any(g in access.groups for g in groups)


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
