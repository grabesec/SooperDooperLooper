"""SDL's HTTP API. Every client (CLI, web GUI, MCP server) goes through it."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime
from importlib.resources import files
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from sdl import __version__
from sdl.core.forwarding import ForwarderStatus
from sdl.core.models import (
    Actor,
    AuditEvent,
    AuditFacets,
    AuditQuery,
    Inventory,
    InventorySource,
    Outcome,
    RolloverRequest,
    RolloverRun,
    TargetSpec,
)
from sdl.core.module import ModuleError
from sdl.core.orchestrator import ConflictError, NotFoundError, Orchestrator, RequestError
from sdl.core.permissions import (
    AUDIT_READ,
    INVENTORY_WRITE,
    MODULES_READ,
    ROLE_PERMISSIONS,
    ROLLOVER_READ,
    ROLLOVER_RUN,
    TARGETS_READ,
    allowed,
)

UI_FILES = {
    "index.html": "text/html; charset=utf-8",
    "app.js": "text/javascript; charset=utf-8",
    "app.css": "text/css; charset=utf-8",
}
UI_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-cache",
}


class ModuleInfo(BaseModel):
    id: str
    kind: str
    type: str
    description: str
    health: dict[str, Any]


class AuditVerification(BaseModel):
    ok: bool
    detail: str


class Me(BaseModel):
    actor: Actor
    permissions: list[str]


@contextmanager
def http_errors() -> Iterator[None]:
    """Turn the core's request errors into HTTP responses."""
    try:
        yield
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except ConflictError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except RequestError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except ModuleError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc


def _matches(system: TargetSpec, q: str | None, group: str | None, source: str | None) -> bool:
    if group is not None and group not in system.groups:
        return False
    if source is not None and system.source != source:
        return False
    if q:
        haystack = " ".join(
            [
                system.name,
                system.hostname or "",
                system.fqdn or "",
                system.host,
                *system.addresses,
                *system.groups,
                system.description or "",
            ]
        ).lower()
        return all(word in haystack for word in q.lower().split())
    return True


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
            query=request.url.query or None,
        )
        request.state.actor = actor
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

    @app.middleware("http")
    async def audit_failures(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Record requests that were let in but then failed, so a refused action shows too."""
        try:
            response = await call_next(request)
        except Exception as exc:
            await _record_failure(request, 500, str(exc) or type(exc).__name__)
            raise
        if response.status_code >= 400:
            await _record_failure(request, response.status_code, None)
        return response

    async def _record_failure(request: Request, code: int, error: str | None) -> None:
        actor = getattr(request.state, "actor", None)
        if actor is None:
            return  # rejected before authentication or authorization: already recorded
        try:
            await orchestrator.audit.record(
                "api.request",
                Outcome.FAILURE,
                actor=actor,
                message=f"{request.method} {request.url.path}",
                status=code,
                error=error,
            )
        except Exception:
            logging.getLogger("sdl.api").exception("could not record a failed request")

    @app.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/", include_in_schema=False)
    async def root() -> RedirectResponse:
        return RedirectResponse("/ui/")

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon() -> Response:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.get("/ui", include_in_schema=False)
    async def ui_redirect() -> RedirectResponse:
        return RedirectResponse("/ui/")

    @app.get("/ui/{name:path}", include_in_schema=False)
    async def ui(name: str) -> Response:
        """The rollover web page: pick systems, run, watch per-system results."""
        name = name or "index.html"
        if name not in UI_FILES:
            raise HTTPException(status.HTTP_404_NOT_FOUND)
        body = files("sdl.api").joinpath("ui", name).read_bytes()
        return Response(body, media_type=UI_FILES[name], headers=UI_HEADERS)

    @app.get("/api/v1/me", tags=["system"])
    async def me(actor: Annotated[Actor, Depends(require(TARGETS_READ))]) -> Me:
        granted = set().union(*(ROLE_PERMISSIONS.get(r, frozenset()) for r in actor.roles))
        return Me(actor=actor, permissions=sorted(granted))

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

    @app.get("/api/v1/systems", tags=["inventory"])
    async def list_systems(
        _: Annotated[Actor, Depends(require(TARGETS_READ))],
        q: Annotated[str | None, Query(description="Words to match in any field.")] = None,
        group: str | None = None,
        source: Annotated[str | None, Query(description="Only this inventory.")] = None,
    ) -> Inventory:
        """Every system from every inventory, with each inventory's status."""
        inventory = await orchestrator.inventory()
        inventory.systems = [s for s in inventory.systems if _matches(s, q, group, source)]
        return inventory

    @app.get("/api/v1/systems/{name}", tags=["inventory"])
    async def get_system(
        name: str, _: Annotated[Actor, Depends(require(TARGETS_READ))]
    ) -> TargetSpec:
        with http_errors():
            return await orchestrator.get_system(name)

    @app.get("/api/v1/targets", tags=["inventory"])
    async def list_targets(
        _: Annotated[Actor, Depends(require(TARGETS_READ))],
    ) -> list[TargetSpec]:
        """Every system, without inventory status (kept for older clients)."""
        return (await orchestrator.inventory()).systems

    @app.get("/api/v1/inventory", tags=["inventory"])
    async def list_inventories(
        _: Annotated[Actor, Depends(require(TARGETS_READ))],
    ) -> list[InventorySource]:
        return (await orchestrator.inventory()).sources

    @app.post("/api/v1/inventory/refresh", tags=["inventory"])
    async def refresh_inventory(
        actor: Annotated[Actor, Depends(require(TARGETS_READ))],
    ) -> list[InventorySource]:
        """Drop cached inventory data (NetBox, ...) and read every source again."""
        return (await orchestrator.refresh_inventory(actor)).sources

    @app.put("/api/v1/inventory/{inventory_id}/systems/{name}", tags=["inventory"])
    async def put_system(
        inventory_id: str,
        name: str,
        body: TargetSpec,
        actor: Annotated[Actor, Depends(require(INVENTORY_WRITE))],
    ) -> TargetSpec:
        """Add a system to a writable inventory, or replace it."""
        if body.name != name:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "name in the body and URL differ")
        with http_errors():
            return await orchestrator.put_system(inventory_id, body, actor)

    @app.delete(
        "/api/v1/inventory/{inventory_id}/systems/{name}",
        tags=["inventory"],
        status_code=status.HTTP_204_NO_CONTENT,
    )
    async def delete_system(
        inventory_id: str,
        name: str,
        actor: Annotated[Actor, Depends(require(INVENTORY_WRITE))],
    ) -> None:
        with http_errors():
            await orchestrator.delete_system(inventory_id, name, actor)

    @app.post("/api/v1/rollovers", tags=["rollovers"], status_code=status.HTTP_202_ACCEPTED)
    async def start_rollover(
        body: RolloverRequest,
        actor: Annotated[Actor, Depends(require(ROLLOVER_RUN))],
        wait: Annotated[bool, Query(description="Return only when the run has finished.")] = False,
        timeout: Annotated[float, Query(gt=0, le=3600)] = 600,
    ) -> RolloverRun:
        with http_errors():
            run = await orchestrator.start_rollover(body, actor)
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
        target: Annotated[
            list[str] | None, Query(description="System (resource) name; repeatable.")
        ] = None,
        module: Annotated[list[str] | None, Query(description="Module instance id.")] = None,
        action: Annotated[
            list[str] | None,
            Query(description="Action type: 'rollover' also matches 'rollover.target.change'."),
        ] = None,
        outcome: Annotated[list[Outcome] | None, Query()] = None,
        actor: Annotated[
            list[str] | None,
            Query(description="User or component id; includes actions done on their behalf."),
        ] = None,
        run_id: str | None = None,
        since: Annotated[datetime | None, Query(description="From (inclusive), ISO 8601.")] = None,
        until: Annotated[datetime | None, Query(description="To (exclusive), ISO 8601.")] = None,
        q: Annotated[str | None, Query(description="Words to find in the message.")] = None,
        limit: Annotated[int, Query(ge=1, le=10000)] = 200,
        order: Annotated[
            Literal["oldest", "newest"], Query(description="Order of the returned events.")
        ] = "oldest",
    ) -> list[AuditEvent]:
        """The ``limit`` most recent events matching every filter given."""
        query = AuditQuery(
            targets=target or [],
            modules=module or [],
            actions=action or [],
            outcomes=outcome or [],
            actors=actor or [],
            run_id=run_id,
            since=since,
            until=until,
            text=q,
            limit=limit,
            newest_first=order == "newest",
        )
        return await orchestrator.audit.primary.query(query)

    @app.get("/api/v1/audit/facets", tags=["audit"])
    async def audit_facets(
        _: Annotated[Actor, Depends(require(AUDIT_READ))],
    ) -> AuditFacets:
        """Systems, modules, action types and actors found in the log, to filter by."""
        return await orchestrator.audit.primary.facets()

    @app.get("/api/v1/forwarders", tags=["audit"])
    async def forwarders(
        _: Annotated[Actor, Depends(require(AUDIT_READ))],
    ) -> list[ForwarderStatus]:
        """Delivery status of every forwarder module (syslog, Graylog, Splunk, ...)."""
        return orchestrator.audit.forwarding.status()

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
