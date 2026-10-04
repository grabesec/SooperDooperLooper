"""SDL's HTTP API. Every client (CLI, web GUI, MCP server) goes through it."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime
from importlib.resources import files
from typing import Annotated, Any, Literal
from urllib.parse import parse_qs, quote, urlencode, urlsplit

from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field, SecretStr

from sdl import __version__
from sdl.core.errors import (
    AuthenticationError,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ProviderUnavailableError,
    RequestError,
)
from sdl.core.forwarding import ForwarderStatus
from sdl.core.identity import (
    LoginResult,
    Me,
    ProviderInfo,
    TotpEnrollment,
    UserCreate,
    UserUpdate,
)
from sdl.core.models import (
    Access,
    Actor,
    AuditEvent,
    AuditFacets,
    AuditQuery,
    ExternalIdentity,
    Inventory,
    InventorySource,
    Outcome,
    RolloverRequest,
    RolloverRun,
    TargetSpec,
    UserView,
)
from sdl.core.module import ModuleError
from sdl.core.orchestrator import Orchestrator
from sdl.core.permissions import (
    ASSIGNABLE_ROLES,
    AUDIT_READ,
    INVENTORY_WRITE,
    MODULES_READ,
    ROLLOVER_READ,
    ROLLOVER_RUN,
    SELF,
    TARGETS_READ,
    USERS_READ,
    USERS_WRITE,
    allowed,
)

MAX_CALLBACK_BODY = 1_000_000
"""Largest single sign-on answer (a SAML response) the callback accepts, in bytes."""

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


class LoginRequest(BaseModel):
    username: str = Field(max_length=255)
    password: SecretStr
    code: str | None = Field(default=None, max_length=16, description="TOTP code, when asked.")
    provider: str | None = Field(
        default=None, description="'local' (default) or a password identity provider id."
    )


class CodeExchange(BaseModel):
    code: str = Field(max_length=128)


class PasswordChange(BaseModel):
    current_password: SecretStr
    new_password: SecretStr


class PasswordSet(BaseModel):
    password: SecretStr
    temporary: bool = Field(
        default=True, description="The user must choose a new password at next sign-in."
    )


class TotpConfirm(BaseModel):
    code: str = Field(max_length=16)


class UserImport(BaseModel):
    username: str
    roles: list[str] = Field(default_factory=list)
    access: Access = Field(default_factory=Access)


class IdentityProviderInfo(ProviderInfo):
    can_search: bool


class RoleInfo(BaseModel):
    name: str
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
    except ForbiddenError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    except AuthenticationError as exc:
        detail: Any = str(exc)
        if exc.mfa_required:
            detail = {"message": str(exc), "mfa_required": True}
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail) from exc
    except ProviderUnavailableError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc
    except RequestError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except ModuleError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc


def client_of(request: Request) -> str | None:
    return request.client.host if request.client else None


def base_url(request: Request) -> str:
    orchestrator: Orchestrator = request.app.state.orchestrator
    configured = orchestrator.settings.api.public_url
    return (configured or str(request.base_url)).rstrip("/")


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
        client = client_of(request)
        actor = await orchestrator.identity.authenticate(request)
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
        request.state.actor = actor
        if permission == SELF:
            return actor  # your own account: not worth an audit event per page load
        await orchestrator.audit.record(
            "api.request",
            Outcome.INFO,
            actor=actor,
            message=where,
            permission=permission,
            client=client,
            query=request.url.query or None,
        )
        return actor

    return dependency


SSO_STATE_COOKIE = "sdl_sso_state"


def _scoped_sources(inventory: Any, actor: Actor) -> list[InventorySource]:
    """Inventory sources as a caller limited to some systems may see them: no error text,
    and only skipped names of systems they reach."""
    if actor.access is None or actor.access.all_systems:
        return list(inventory.sources)
    names = {s.name for s in inventory.systems}
    return [
        src.model_copy(
            update={
                "skipped": [n for n in src.skipped if n in names],
                "error": None if src.error is None else "unavailable",
            }
        )
        for src in inventory.sources
    ]


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

    identity = orchestrator.identity
    if not orchestrator.settings.api.public_url and any(
        p.login == "redirect" for p in identity.list_providers()
    ):
        # Without it, callback URLs (and the SAML audience) follow the Host header.
        raise RuntimeError("single sign-on is configured: set api.public_url")

    # -- sign-in ------------------------------------------------------------------------

    @app.get("/api/v1/auth/providers", tags=["auth"])
    async def auth_providers() -> list[ProviderInfo]:
        """How people can sign in: SDL's own form, LDAP, single sign-on providers."""
        return identity.list_providers()

    @app.post("/api/v1/auth/login", tags=["auth"])
    async def login(body: LoginRequest, request: Request) -> LoginResult:
        """Sign in with a user name and password (and TOTP code); returns a session token.

        Answers 401 with ``{"mfa_required": true}`` when the password was right
        and a one-time code is needed.
        """
        with http_errors():
            return await identity.login(
                body.username,
                body.password.get_secret_value(),
                body.code,
                body.provider,
                client_of(request),
            )

    @app.get("/api/v1/auth/sso/{provider}/start", tags=["auth"])
    async def sso_start(
        provider: str,
        request: Request,
        return_to: Annotated[Literal["ui", "cli"], Query()] = "ui",
    ) -> RedirectResponse:
        """Send the browser to the identity provider's sign-in page."""
        with http_errors():
            url = await identity.sso_begin(provider, _callback(request, provider), return_to)
        response = RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)
        state = parse_qs(urlsplit(url).query).get("state", [""])[0]
        if state:
            # Bind the sign-in to this browser (login CSRF): the callback must come back
            # with the same state.
            response.set_cookie(
                SSO_STATE_COOKIE,
                _state_hash(state),
                max_age=600,
                path="/api/v1/auth/sso",
                httponly=True,
                samesite="lax",
                secure=base_url(request).startswith("https://"),
            )
        return response

    def _state_hash(state: str) -> str:
        return hashlib.sha256(state.encode()).hexdigest()

    def _sso_error(code: str) -> RedirectResponse:
        response = RedirectResponse(
            "/ui/#" + urlencode({"sso_error": code}), status_code=status.HTTP_303_SEE_OTHER
        )
        response.delete_cookie(SSO_STATE_COOKIE, path="/api/v1/auth/sso")
        return response

    def _callback(request: Request, provider: str) -> str:
        return f"{base_url(request)}/api/v1/auth/sso/{quote(provider, safe='')}/callback"

    @app.api_route("/api/v1/auth/sso/{provider}/callback", methods=["GET", "POST"], tags=["auth"])
    async def sso_callback(provider: str, request: Request) -> RedirectResponse:
        """Where the identity provider sends the browser back (query string or form post)."""
        params = dict(request.query_params.items())
        if request.method == "POST":
            if int(request.headers.get("content-length") or 0) > MAX_CALLBACK_BODY:
                raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)
            body = b""
            async for chunk in request.stream():
                body += chunk
                if len(body) > MAX_CALLBACK_BODY:
                    raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)
            params.update(
                {k: v[0] for k, v in parse_qs(body.decode("utf-8", "replace")).items() if v}
            )
        # SAML posts back cross-site, where a SameSite=Lax cookie is not sent; the state
        # cookie is checked on the OIDC (``state``) flow.
        if "state" in params:
            cookie = request.cookies.get(SSO_STATE_COOKIE) or ""
            if not hmac.compare_digest(cookie, _state_hash(params["state"])):
                return _sso_error("state_mismatch")
        try:
            with http_errors():
                code, return_to = await identity.sso_complete(
                    provider, params, _callback(request, provider), client_of(request)
                )
        except HTTPException as exc:
            logging.getLogger("sdl.api").info(
                "single sign-on with %s failed: %s", provider, exc.detail
            )
            return _sso_error("unavailable" if exc.status_code >= 500 else "failed")
        key = "cli_code" if return_to == "cli" else "sso"
        response = RedirectResponse(
            "/ui/#" + urlencode({key: code}), status_code=status.HTTP_303_SEE_OTHER
        )
        response.delete_cookie(SSO_STATE_COOKIE, path="/api/v1/auth/sso")
        return response

    @app.get("/api/v1/auth/sso/{provider}/metadata", tags=["auth"])
    async def sso_metadata(provider: str, request: Request) -> Response:
        """Service-provider metadata to register SDL with a SAML identity provider."""
        with http_errors():
            idp = identity.provider(provider)
        xml = idp.metadata(_callback(request, provider))
        if xml is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "this provider has no metadata")
        return Response(xml, media_type="application/samlmetadata+xml")

    @app.post("/api/v1/auth/sso/exchange", tags=["auth"])
    async def sso_exchange(body: CodeExchange) -> LoginResult:
        """Trade the one-time code a single sign-on handed the page for a session token."""
        with http_errors():
            return await identity.exchange(body.code)

    @app.post("/api/v1/auth/logout", tags=["auth"], status_code=status.HTTP_204_NO_CONTENT)
    async def logout(request: Request, actor: Annotated[Actor, Depends(require(SELF))]) -> None:
        await identity.logout(actor, request)

    # -- your own account ------------------------------------------------------------------

    @app.get("/api/v1/me", tags=["me"])
    async def me(request: Request, actor: Annotated[Actor, Depends(require(SELF))]) -> Me:
        """Who you are, what you may do, which systems you reach, and what is pending."""
        return await identity.me(actor, request)

    @app.post("/api/v1/me/password", tags=["me"], status_code=status.HTTP_204_NO_CONTENT)
    async def change_password(
        body: PasswordChange, request: Request, actor: Annotated[Actor, Depends(require(SELF))]
    ) -> None:
        with http_errors():
            await identity.change_own_password(
                actor,
                request,
                body.current_password.get_secret_value(),
                body.new_password.get_secret_value(),
            )

    @app.post("/api/v1/me/mfa/totp", tags=["me"])
    async def begin_totp(
        request: Request, actor: Annotated[Actor, Depends(require(SELF))]
    ) -> TotpEnrollment:
        """Start setting up an authenticator app; confirm it with a code to finish."""
        with http_errors():
            return await identity.begin_totp(actor, request)

    @app.post("/api/v1/me/mfa/totp/confirm", tags=["me"], status_code=status.HTTP_204_NO_CONTENT)
    async def confirm_totp(
        body: TotpConfirm, request: Request, actor: Annotated[Actor, Depends(require(SELF))]
    ) -> None:
        with http_errors():
            await identity.confirm_totp(actor, request, body.code)

    # -- user management -----------------------------------------------------------------

    @app.get("/api/v1/roles", tags=["users"])
    async def list_roles(_: Annotated[Actor, Depends(require(SELF))]) -> list[RoleInfo]:
        from sdl.core.permissions import ROLE_PERMISSIONS

        return [
            RoleInfo(name=name, permissions=sorted(ROLE_PERMISSIONS[name]))
            for name in sorted(ASSIGNABLE_ROLES)
        ]

    @app.get("/api/v1/users", tags=["users"])
    async def list_users(_: Annotated[Actor, Depends(require(USERS_READ))]) -> list[UserView]:
        with http_errors():
            return await identity.list_users()

    @app.post("/api/v1/users", tags=["users"], status_code=status.HTTP_201_CREATED)
    async def create_user(
        body: UserCreate, actor: Annotated[Actor, Depends(require(USERS_WRITE))]
    ) -> UserView:
        """Add a local user, with roles and the inventory groups and systems they may reach."""
        with http_errors():
            return await identity.create_user(actor, body)

    @app.get("/api/v1/users/{name}", tags=["users"])
    async def get_user(name: str, _: Annotated[Actor, Depends(require(USERS_READ))]) -> UserView:
        with http_errors():
            return await identity.get_user(name)

    @app.patch("/api/v1/users/{name}", tags=["users"])
    async def update_user(
        name: str, body: UserUpdate, actor: Annotated[Actor, Depends(require(USERS_WRITE))]
    ) -> UserView:
        """Change a user's details, roles, assigned groups and systems, or enable/disable them."""
        with http_errors():
            return await identity.update_user(actor, name, body)

    @app.delete("/api/v1/users/{name}", tags=["users"], status_code=status.HTTP_204_NO_CONTENT)
    async def delete_user(
        name: str, actor: Annotated[Actor, Depends(require(USERS_WRITE))]
    ) -> None:
        with http_errors():
            await identity.delete_user(actor, name)

    @app.post(
        "/api/v1/users/{name}/password", tags=["users"], status_code=status.HTTP_204_NO_CONTENT
    )
    async def set_password(
        name: str, body: PasswordSet, actor: Annotated[Actor, Depends(require(USERS_WRITE))]
    ) -> None:
        """Set a local user's password; by default they must change it at next sign-in."""
        with http_errors():
            await identity.set_password(
                actor, name, body.password.get_secret_value(), body.temporary
            )

    @app.delete("/api/v1/users/{name}/mfa", tags=["users"], status_code=status.HTTP_204_NO_CONTENT)
    async def reset_mfa(name: str, actor: Annotated[Actor, Depends(require(USERS_WRITE))]) -> None:
        """Remove a user's authenticator (lost phone); they set up a new one at next sign-in."""
        with http_errors():
            await identity.reset_mfa(actor, name)

    @app.post("/api/v1/users/{name}/unlock", tags=["users"], status_code=status.HTTP_204_NO_CONTENT)
    async def unlock_user(
        name: str, actor: Annotated[Actor, Depends(require(USERS_WRITE))]
    ) -> None:
        """Clear a lockout after too many failed sign-ins."""
        with http_errors():
            await identity.unlock(actor, name)

    @app.get("/api/v1/idps", tags=["users"])
    async def list_idps(
        _: Annotated[Actor, Depends(require(USERS_READ))],
    ) -> list[IdentityProviderInfo]:
        """Identity-provider modules (LDAP / Active Directory, Entra ID and other OIDC, SAML)."""
        return [
            IdentityProviderInfo(
                **info.model_dump(), can_search=identity.providers[info.id].can_search
            )
            for info in identity.list_providers()
            if info.id in identity.providers
        ]

    @app.get("/api/v1/idps/{provider}/users", tags=["users"])
    async def search_directory(
        provider: str,
        actor: Annotated[Actor, Depends(require(USERS_WRITE))],
        q: Annotated[str, Query(max_length=200)] = "",
        limit: Annotated[int, Query(ge=1, le=500)] = 50,
    ) -> list[ExternalIdentity]:
        """Look users up in a directory (LDAP / Active Directory) to add them to SDL."""
        with http_errors():
            return await identity.search_directory(actor, provider, q, limit)

    @app.post("/api/v1/idps/{provider}/users", tags=["users"], status_code=status.HTTP_201_CREATED)
    async def import_user(
        provider: str,
        actor: Annotated[Actor, Depends(require(USERS_WRITE))],
        body: Annotated[UserImport, Body()],
    ) -> UserView:
        """Add a directory user to SDL before their first sign-in, with roles and access."""
        with http_errors():
            return await identity.import_user(
                actor, provider, body.username, body.roles, body.access
            )

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
        actor: Annotated[Actor, Depends(require(TARGETS_READ))],
        q: Annotated[str | None, Query(description="Words to match in any field.")] = None,
        group: str | None = None,
        source: Annotated[str | None, Query(description="Only this inventory.")] = None,
    ) -> Inventory:
        """Every system assigned to the caller, from every inventory, with each inventory's
        status."""
        inventory = await orchestrator.visible_inventory(actor)
        inventory.sources = _scoped_sources(inventory, actor)
        inventory.systems = [s for s in inventory.systems if _matches(s, q, group, source)]
        return inventory

    @app.get("/api/v1/systems/{name}", tags=["inventory"])
    async def get_system(
        name: str, actor: Annotated[Actor, Depends(require(TARGETS_READ))]
    ) -> TargetSpec:
        with http_errors():
            return await orchestrator.get_system(name, actor)

    @app.get("/api/v1/targets", tags=["inventory"])
    async def list_targets(
        actor: Annotated[Actor, Depends(require(TARGETS_READ))],
    ) -> list[TargetSpec]:
        """Every system, without inventory status (kept for older clients)."""
        return (await orchestrator.visible_inventory(actor)).systems

    @app.get("/api/v1/inventory", tags=["inventory"])
    async def list_inventories(
        actor: Annotated[Actor, Depends(require(TARGETS_READ))],
    ) -> list[InventorySource]:
        return _scoped_sources(await orchestrator.visible_inventory(actor), actor)

    @app.post("/api/v1/inventory/refresh", tags=["inventory"])
    async def refresh_inventory(
        actor: Annotated[Actor, Depends(require(INVENTORY_WRITE))],
    ) -> list[InventorySource]:
        """Drop cached inventory data (NetBox, ...) and read every source again."""
        await orchestrator.refresh_inventory(actor)
        return _scoped_sources(await orchestrator.visible_inventory(actor), actor)

    @app.put("/api/v1/inventory/{inventory_id}/systems/{name}", tags=["inventory"])
    async def put_system(
        inventory_id: str,
        name: str,
        body: TargetSpec,
        actor: Annotated[Actor, Depends(require(INVENTORY_WRITE))],
    ) -> TargetSpec:
        """Add a system to a writable inventory, or replace it.

        Callers limited to some groups and systems can only store systems within them.
        """
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
        return orchestrator.visible_run(run, actor) or run

    @app.get("/api/v1/rollovers", tags=["rollovers"])
    async def list_rollovers(
        actor: Annotated[Actor, Depends(require(ROLLOVER_READ))],
    ) -> list[RolloverRun]:
        """Runs, newest first; each shows only the systems assigned to the caller."""
        return orchestrator.visible_runs(actor)

    @app.get("/api/v1/rollovers/{run_id}", tags=["rollovers"])
    async def get_rollover(
        run_id: str,
        actor: Annotated[Actor, Depends(require(ROLLOVER_READ))],
    ) -> RolloverRun:
        run = orchestrator.runs.get(run_id)
        run = orchestrator.visible_run(run, actor) if run is not None else None
        if run is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such rollover run")
        return run

    @app.get("/api/v1/audit", tags=["audit"])
    async def query_audit(
        caller: Annotated[Actor, Depends(require(AUDIT_READ))],
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
        """The ``limit`` most recent events matching every filter given.

        Callers limited to some systems see events about those systems and their own actions.
        """
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
        query = await orchestrator.audit_scope(caller, query)
        return await orchestrator.audit.primary.query(query)

    @app.get("/api/v1/audit/facets", tags=["audit"])
    async def audit_facets(
        actor: Annotated[Actor, Depends(require(AUDIT_READ))],
    ) -> AuditFacets:
        """Systems, modules, action types and actors found in the log, to filter by."""
        query = await orchestrator.audit_scope(actor, AuditQuery())
        scoped = query if query.scope_targets is not None else None
        return await orchestrator.audit.primary.facets(scoped)

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
