"""SDL's HTTP API. Every client (CLI, web GUI, MCP server) goes through it."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from pydantic import BaseModel

from sdl import __version__
from sdl.core.models import Actor, AuditEvent, Outcome, RolloverRequest, RolloverRun, TargetSpec
from sdl.core.orchestrator import Orchestrator, RequestError
from sdl.core.permissions import (
    AUDIT_READ,
    MODULES_READ,
    ROLLOVER_READ,
    ROLLOVER_RUN,
    TARGETS_READ,
    allowed,
)


class ModuleInfo(BaseModel):
    id: str
    kind: str
    type: str
    description: str
    health: dict[str, Any]


class AuditVerification(BaseModel):
    ok: bool
    detail: str


def require(permission: str) -> Callable[[Request], Awaitable[Actor]]:
    """Dependency: authenticate the caller, check the permission, and audit the request."""

    async def dependency(request: Request) -> Actor:
        orchestrator: Orchestrator = request.app.state.orchestrator
        where = f"{request.method} {request.url.path}"
        client = request.client.host if request.client else None
        actor = await orchestrator.auth_module().authenticate(request)
        if actor is None:
            await orchestrator.audit.record(
                "api.authenticate", Outcome.DENIED, message=where, client=client
            )
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                "missing or invalid credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not allowed(actor, permission):
            await orchestrator.audit.record(
                "api.authorize",
                Outcome.DENIED,
                actor=actor,
                message=where,
                permission=permission,
                client=client,
            )
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"{permission} is not granted")
        await orchestrator.audit.record(
            "api.request",
            Outcome.INFO,
            actor=actor,
            message=where,
            permission=permission,
            client=client,
        )
        return actor

    return dependency


def create_app(orchestrator: Orchestrator) -> FastAPI:
    orchestrator.load()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        await orchestrator.start()
        try:
            yield
        finally:
            await orchestrator.stop()

    app = FastAPI(
        title="SooperDooperLooper",
        version=__version__,
        description="Secret rollover orchestrator API.",
        lifespan=lifespan,
    )
    app.state.orchestrator = orchestrator

    @app.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/api/v1/modules", tags=["system"])
    async def list_modules(
        _: Annotated[Actor, Depends(require(MODULES_READ))],
    ) -> list[ModuleInfo]:
        async def info(instance_id: str) -> ModuleInfo:
            module = orchestrator.modules[instance_id]
            try:
                health = await asyncio.wait_for(module.health(), 10)
            except Exception as exc:
                health = {"ok": False, "error": str(exc)}
            return ModuleInfo(
                id=instance_id,
                kind=module.kind.value,
                type=orchestrator.settings.modules[instance_id].type,
                description=module.description,
                health=health,
            )

        return list(await asyncio.gather(*(info(i) for i in orchestrator.modules)))

    @app.get("/api/v1/targets", tags=["targets"])
    async def list_targets(
        _: Annotated[Actor, Depends(require(TARGETS_READ))],
    ) -> list[TargetSpec]:
        return orchestrator.targets

    @app.post("/api/v1/rollovers", tags=["rollovers"], status_code=status.HTTP_202_ACCEPTED)
    async def start_rollover(
        body: RolloverRequest,
        actor: Annotated[Actor, Depends(require(ROLLOVER_RUN))],
        wait: Annotated[bool, Query(description="Return only when the run has finished.")] = False,
        timeout: Annotated[float, Query(gt=0, le=3600)] = 600,
    ) -> RolloverRun:
        try:
            run = await orchestrator.start_rollover(body, actor)
        except RequestError as exc:
            code = (
                status.HTTP_409_CONFLICT
                if "in progress" in str(exc)
                else status.HTTP_400_BAD_REQUEST
            )
            raise HTTPException(code, str(exc)) from exc
        if wait:
            try:
                run = await orchestrator.wait(run.id, timeout)
            except TimeoutError:
                pass  # still running; the caller polls GET /rollovers/{id}
        return run

    @app.get("/api/v1/rollovers", tags=["rollovers"])
    async def list_rollovers(
        _: Annotated[Actor, Depends(require(ROLLOVER_READ))],
    ) -> list[RolloverRun]:
        return sorted(orchestrator.runs.values(), key=lambda r: r.created_at, reverse=True)

    @app.get("/api/v1/rollovers/{run_id}", tags=["rollovers"])
    async def get_rollover(
        run_id: str,
        _: Annotated[Actor, Depends(require(ROLLOVER_READ))],
    ) -> RolloverRun:
        run = orchestrator.runs.get(run_id)
        if run is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such rollover run")
        return run

    @app.get("/api/v1/audit", tags=["audit"])
    async def query_audit(
        _: Annotated[Actor, Depends(require(AUDIT_READ))],
        run_id: str | None = None,
        target: str | None = None,
        limit: Annotated[int, Query(ge=1, le=10000)] = 200,
    ) -> list[AuditEvent]:
        return await orchestrator.audit.primary.query(run_id=run_id, target=target, limit=limit)

    @app.get("/api/v1/audit/verify", tags=["audit"])
    async def verify_audit(
        _: Annotated[Actor, Depends(require(AUDIT_READ))],
    ) -> AuditVerification:
        ok, detail = await orchestrator.audit.primary.verify()
        return AuditVerification(ok=ok, detail=detail)

    for instance_id, module in orchestrator.modules.items():
        router = module.router()
        if router is not None:
            app.include_router(router, prefix=f"/api/v1/modules/{instance_id}", tags=[instance_id])

    return app
