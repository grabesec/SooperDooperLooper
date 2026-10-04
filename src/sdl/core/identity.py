"""Identity: who can sign in, how, and what each user may reach.

The core keeps sign-in in one place so every way in gets the same rules
(password policy, lockout, MFA, audit):

* the **superuser**, from its own file (``sdl.core.superuser``);
* **local users**, kept by the user-store module, with a password and an
  optional TOTP authenticator;
* users of **identity-provider modules** (LDAP / Active Directory, OpenID
  Connect for Entra ID and others, SAML), whose provider groups are mapped to
  SDL roles, inventory groups and systems;
* **API tokens** of machine clients, checked by auth modules.

People who sign in get a session token, used as a bearer token like an API
token. Sessions live in memory: restarting SDL signs everyone out. Each
request re-reads the user's record, so disabling a user or changing what they
are assigned applies at once.
"""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
import logging
import re
import secrets
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field, SecretStr

from sdl.core import passwords, superuser, totp
from sdl.core.errors import (
    AuthenticationError,
    ConfigError,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ProviderUnavailableError,
    RequestError,
)
from sdl.core.models import (
    LOCAL_SOURCE,
    USER_NAME_PATTERN,
    Access,
    Actor,
    ActorType,
    ExternalIdentity,
    Outcome,
    UserRecord,
    UserView,
    utcnow,
)
from sdl.core.module import AuthModule, IdentityProviderModule, ModuleError, UserStoreModule
from sdl.core.permissions import SUPERUSER_ROLE, check_roles, permissions_of

if TYPE_CHECKING:
    from fastapi import Request

    from sdl.core.audit import AuditRecorder
    from sdl.core.settings import ApiSettings, IdentitySettings

log = logging.getLogger("sdl.identity")

SESSION_PREFIX = "sdls_"
SSO_STATE_TTL = 600.0
SSO_CODE_TTL = 60.0
MAX_PENDING_SSO = 10_000
"""Single sign-ons started but not finished; more are refused (anyone can start one)."""
TOTP_ENROLL_TTL = 600.0
SUPERUSER_PROVIDER = "superuser"

PENDING_PASSWORD = "password_change"  # noqa: S105 - a state name, not a password
PENDING_MFA = "mfa_enrollment"


class SessionKind(StrEnum):
    SUPERUSER = "superuser"
    LOCAL = "local"
    PROVIDER = "provider"


@dataclass
class Session:
    name: str
    kind: SessionKind
    provider: str
    display_name: str | None
    expires: float
    last_seen: float
    external_groups: list[str] = field(default_factory=list)
    pending: set[str] = field(default_factory=set)
    superuser_mtime: float | None = None
    created: float = field(default_factory=time.time)


@dataclass
class _Pending:
    provider: str
    state: dict[str, Any]
    return_to: str
    expires: float


class ProviderInfo(BaseModel):
    id: str
    name: str
    type: str
    login: str = Field(description="'password' (SDL's form) or 'redirect' (single sign-on).")


class LoginResult(BaseModel):
    token: str
    expires_at: datetime
    actor: Actor
    pending: list[str] = Field(
        default_factory=list,
        description="What the user must do before anything else: 'password_change', "
        "'mfa_enrollment'.",
    )


class Me(BaseModel):
    actor: Actor
    permissions: list[str]
    access: Access | None = Field(description="Systems within reach; null means every system.")
    signed_in_with: str | None = Field(
        default=None,
        description="'superuser', 'local' or an identity provider id; null for API tokens.",
    )
    pending: list[str] = Field(default_factory=list)
    can_change_password: bool = False
    mfa: bool = False
    session_expires_at: datetime | None = None


class TotpEnrollment(BaseModel):
    secret: str
    uri: str = Field(description="otpauth:// link for authenticator apps.")


class UserCreate(BaseModel):
    name: str
    display_name: str | None = None
    email: str | None = None
    password: SecretStr | None = Field(
        default=None, description="Initial password; the user must change it at first sign-in."
    )
    roles: list[str] = Field(default_factory=list)
    access: Access = Field(default_factory=Access)
    enabled: bool = True


class UserUpdate(BaseModel):
    display_name: str | None = None
    email: str | None = None
    roles: list[str] | None = None
    access: Access | None = None
    enabled: bool | None = None


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _ts(value: float) -> datetime:
    return datetime.fromtimestamp(value, UTC)


USER_LOCKOUT_FACTOR = 4  # per-user backstop, over all clients
FAILURE_WINDOW = 3600.0  # seconds a failure counter is kept without new failures
MAX_FAILURE_ENTRIES = 10_000

_attempt_reserved: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "sdl_attempt_reserved", default=False
)


class Identity:
    def __init__(
        self,
        settings: IdentitySettings,
        api: ApiSettings,
        audit: AuditRecorder,
        users: UserStoreModule | None,
        providers: list[IdentityProviderModule],
        auth_modules: list[AuthModule],
        types: dict[str, str],
    ) -> None:
        self.settings = settings
        self.api = api
        self.audit = audit
        self.users = users
        self.providers = {p.instance_id: p for p in providers}
        self.auth_modules = auth_modules
        self._types = types
        self._sessions: dict[str, Session] = {}
        self._sso: dict[str, _Pending] = {}
        self._codes: dict[str, tuple[str, float]] = {}
        # failed sign-ins: "<provider>:<name>" (all clients) and "<provider>:<name>|<client>"
        # -> (count, locked until, last failure)
        self._failures: dict[str, tuple[int, float, float]] = {}
        self._totp_last: dict[str, int] = {}
        self._totp_enroll: dict[str, tuple[str, float]] = {}
        self._lock = asyncio.Lock()
        self._validate()

    def _validate(self) -> None:
        for provider in self.providers.values():
            if provider.instance_id in (LOCAL_SOURCE, SUPERUSER_PROVIDER):
                raise ConfigError(f"{provider.instance_id!r} is reserved and cannot be a module id")
            roles = list(provider.config.default_roles)
            roles += [r for m in provider.config.group_mapping for r in m.roles]
            try:
                check_roles(roles)
            except ValueError as exc:
                raise ConfigError(f"identity provider {provider.instance_id!r}: {exc}") from exc
            if provider.login not in ("password", "redirect"):
                raise ConfigError(f"identity provider {provider.instance_id!r}: unknown login type")
            if getattr(provider.config, "require_totp", False) and self.users is None:
                raise ConfigError(
                    f"identity provider {provider.instance_id!r} has require_totp set, but no "
                    "users module is configured to keep the authenticators"
                )
        path = self.settings.superuser_file
        if path is not None:
            try:
                superuser.load(path)
            except superuser.SuperuserFileError as exc:
                raise ConfigError(str(exc)) from exc
        if not (path or self.users or self.providers or self.auth_modules):
            raise ConfigError(
                "nobody can sign in: configure identity.superuser_file, a users module, "
                "an identity provider or an auth module"
            )

    # -- sign-in -------------------------------------------------------------------

    def list_providers(self) -> list[ProviderInfo]:
        found = []
        if self.settings.superuser_file or self.users:
            found.append(ProviderInfo(id=LOCAL_SOURCE, name="SDL", type="local", login="password"))
        for provider in self.providers.values():
            found.append(
                ProviderInfo(
                    id=provider.instance_id,
                    name=provider.display_name,
                    type=self._types.get(provider.instance_id, provider.kind.value),
                    login=provider.login,
                )
            )
        return found

    def _keys(self, key: str, client: str | None) -> list[tuple[str, int]]:
        """The failure counters a sign-in touches, with the count that locks each: one per
        (user, client) when the client is known, and a higher one for the user as a backstop,
        so a remote attacker cannot easily lock a user out from everywhere."""
        limit = self.settings.max_failed_logins
        if client:
            return [(f"{key}|{client}", limit), (key, limit * USER_LOCKOUT_FACTOR)]
        return [(key, limit)]

    def _prune_failures(self, now: float) -> None:
        window = max(self.settings.lockout, FAILURE_WINDOW)
        for k, (_, until, last) in list(self._failures.items()):
            if until <= now and last + window <= now:
                del self._failures[k]
        if len(self._failures) > MAX_FAILURE_ENTRIES:
            oldest = sorted(self._failures, key=lambda k: self._failures[k][2])
            for k in oldest[: len(self._failures) - MAX_FAILURE_ENTRIES]:
                del self._failures[k]

    def _locked(self, key: str, client: str | None = None) -> bool:
        now = time.time()
        locked = False
        for k, _ in self._keys(key, client):
            _count, until, _last = self._failures.get(k, (0, 0.0, 0.0))
            if until and until > now:
                locked = True
            elif until:
                self._failures.pop(k, None)
        return locked

    def _failed(self, key: str, client: str | None = None) -> None:
        now = time.time()
        self._prune_failures(now)
        for k, limit in self._keys(key, client):
            count, _, _ = self._failures.get(k, (0, 0.0, 0.0))
            count += 1
            until = 0.0
            if count >= limit and self.settings.lockout > 0:
                until = now + self.settings.lockout
            self._failures[k] = (count, until, now)

    def _release(self, key: str, client: str | None) -> None:
        """Give back an attempt reserved before checking it, when it did not fail."""
        for k, _ in self._keys(key, client):
            count, until, last = self._failures.get(k, (0, 0.0, 0.0))
            if count <= 1 and not until:
                self._failures.pop(k, None)
            elif count:
                self._failures[k] = (count - 1, until, last)

    def _clear_failures(self, key: str) -> None:
        for k in [k for k in self._failures if k == key or k.startswith(f"{key}|")]:
            del self._failures[k]

    async def _refuse(
        self,
        username: str,
        provider: str,
        reason: str,
        client: str | None,
        *,
        outcome: Outcome = Outcome.FAILURE,
        count: bool = True,
        public: str = "wrong user name, password or code",
    ) -> AuthenticationError:
        if count and not _attempt_reserved.get():
            self._failed(f"{provider}:{username}", client)
        error = AuthenticationError(public)
        error.counted = count  # type: ignore[attr-defined]
        await self.audit.record(
            "auth.login",
            outcome,
            actor=Actor(type=ActorType.USER, id=username or "-"),
            module=None if provider in (LOCAL_SOURCE, SUPERUSER_PROVIDER) else provider,
            message=reason,
            provider=provider,
            client=client,
        )
        return error

    def _check_code(self, key: str, secret: SecretStr, code: str | None) -> bool:
        last = self._totp_last.get(key, -1)
        step = totp.verify(secret.get_secret_value(), code or "", after_step=last)
        if step is None:
            return False
        self._totp_last[key] = step
        return True

    async def login(
        self,
        username: str,
        password: str,
        code: str | None = None,
        provider: str | None = None,
        client: str | None = None,
    ) -> LoginResult:
        """Check a user name and password (and TOTP code) and open a session."""
        username = username.strip().lower()
        provider = provider or LOCAL_SOURCE
        key = f"{provider}:{username}"
        if not username or not password:
            raise await self._refuse(username, provider, "empty user name or password", client)
        if self._locked(key, client):
            raise await self._refuse(
                username,
                provider,
                "account locked after too many failed sign-ins",
                client,
                outcome=Outcome.DENIED,
                count=False,
                public="too many failed sign-ins; try again later",
            )
        # Count the attempt before the (slow, awaited) checks so parallel requests cannot
        # get past the lockout; give it back when it did not fail on credentials.
        self._failed(key, client)
        reserved = _attempt_reserved.set(True)
        try:
            result = await self._login_checked(username, password, code, provider, client)
        except AuthenticationError as exc:
            if not getattr(exc, "counted", False):
                self._release(key, client)
            raise
        except BaseException:
            self._release(key, client)
            raise
        finally:
            _attempt_reserved.reset(reserved)
        self._clear_failures(key)
        return result

    async def _login_checked(
        self, username: str, password: str, code: str | None, provider: str, client: str | None
    ) -> LoginResult:
        if provider == LOCAL_SOURCE:
            result = await self._login_local(username, password, code, client)
        else:
            idp = self.providers.get(provider)
            if idp is None or idp.login != "password":
                raise AuthenticationError(f"no password sign-in provider named {provider!r}")
            try:
                identity = await idp.authenticate(username, password)
            except Exception as exc:
                await self.audit.record(
                    "auth.login",
                    Outcome.FAILURE,
                    actor=Actor(type=ActorType.USER, id=username),
                    module=provider,
                    message=f"identity provider error: {exc}",
                    provider=provider,
                    client=client,
                )
                raise ProviderUnavailableError(
                    f"{idp.display_name} could not be reached; try again later"
                ) from exc
            if identity is None:
                raise await self._refuse(username, provider, "wrong user name or password", client)
            result = await self._login_external(idp, identity, client, code=code)
        return result

    def _superuser(self) -> superuser.Superuser | None:
        path = self.settings.superuser_file
        if path is None:
            return None
        try:
            return superuser.load(path)
        except superuser.SuperuserFileError:
            log.exception("cannot use the superuser file")
            return None

    async def _login_local(
        self, username: str, password: str, code: str | None, client: str | None
    ) -> LoginResult:
        su = self._superuser()
        if su is not None and su.name == username:
            if not await asyncio.to_thread(passwords.verify_password, su.password_hash, password):
                raise await self._refuse(username, SUPERUSER_PROVIDER, "wrong password", client)
            if su.totp_secret is not None:
                await self._need_code(username, SUPERUSER_PROVIDER, su.totp_secret, code, client)
            session = Session(
                name=su.name,
                kind=SessionKind.SUPERUSER,
                provider=SUPERUSER_PROVIDER,
                display_name=su.display_name or "SDL superuser",
                expires=0,
                last_seen=0,
                superuser_mtime=self._superuser_mtime(),
            )
            return await self._open(session, client, mfa=su.totp_secret is not None)

        record = await self.users.get_user(username) if self.users else None
        if record is not None and not record.local:
            record = None
        known_hash = record.password_hash if record else None
        if not await asyncio.to_thread(passwords.verify_password, known_hash, password):
            raise await self._refuse(username, LOCAL_SOURCE, "wrong user name or password", client)
        assert record is not None and self.users is not None
        if not record.enabled:
            raise await self._refuse(
                username,
                LOCAL_SOURCE,
                "account is disabled",
                client,
                outcome=Outcome.DENIED,
                public="this account is disabled",
            )
        if record.totp_secret is not None:
            await self._need_code(username, LOCAL_SOURCE, record.totp_secret, code, client)
        if not record.roles and not record.must_change_password:
            raise await self._refuse(
                username,
                LOCAL_SOURCE,
                "user has no role",
                client,
                outcome=Outcome.DENIED,
                count=False,
                public="this account has not been given access to SDL yet",
            )
        record.last_login = utcnow()
        if record.password_hash and passwords.needs_rehash(record.password_hash):
            record.password_hash = passwords.hash_password(password)
        await self.users.put_user(record)
        pending = set()
        if record.must_change_password:
            pending.add(PENDING_PASSWORD)
        if self.settings.require_mfa and not record.mfa:
            pending.add(PENDING_MFA)
        session = Session(
            name=record.name,
            kind=SessionKind.LOCAL,
            provider=LOCAL_SOURCE,
            display_name=record.display_name,
            expires=0,
            last_seen=0,
            pending=pending,
        )
        return await self._open(session, client, mfa=record.mfa)

    async def _need_code(
        self, username: str, provider: str, secret: SecretStr, code: str | None, client: str | None
    ) -> None:
        if not code:
            raise AuthenticationError(
                "enter the code from your authenticator app", mfa_required=True
            )
        if not self._check_code(f"{provider}:{username}", secret, code):
            raise await self._refuse(username, provider, "wrong or reused one-time code", client)

    def _mapped(
        self, idp: IdentityProviderModule, groups: list[str], record: UserRecord | None
    ) -> tuple[list[str], Access]:
        member_of = {g.lower() for g in groups}
        roles = set(idp.config.default_roles)
        access = Access()
        for mapping in idp.config.group_mapping:
            if mapping.group.lower() in member_of:
                roles.update(mapping.roles)
                access = access.union(mapping.access)
        if record is not None:
            roles.update(record.roles)
            access = access.union(record.access)
        return sorted(roles), access

    async def _login_external(
        self,
        idp: IdentityProviderModule,
        identity: ExternalIdentity,
        client: str | None,
        *,
        code: str | None = None,
    ) -> LoginResult:
        name = identity.username
        provider = idp.instance_id
        if not re.fullmatch(USER_NAME_PATTERN, name):
            raise await self._refuse(
                name[:255],
                provider,
                f"user name {name!r} has characters SDL does not allow in names",
                client,
                outcome=Outcome.DENIED,
                count=False,
                public="your user name cannot be used in SDL; ask an administrator",
            )
        su = self._superuser()
        if su is not None and su.name == name:
            raise await self._refuse(
                name,
                provider,
                "the superuser cannot sign in through an identity provider",
                client,
                outcome=Outcome.DENIED,
                public="this account cannot sign in here",
            )
        record = await self.users.get_user(name) if self.users else None
        if record is not None and record.source != provider:
            raise await self._refuse(
                name,
                provider,
                f"a user named {name!r} already comes from {record.source!r}",
                client,
                outcome=Outcome.DENIED,
                public="another account already has this name in SDL; ask an administrator",
            )
        if record is not None and not record.enabled:
            raise await self._refuse(
                name,
                provider,
                "account is disabled in SDL",
                client,
                outcome=Outcome.DENIED,
                public="this account is disabled",
            )
        roles, _ = self._mapped(idp, identity.groups, record)
        if not roles:
            raise await self._refuse(
                name,
                provider,
                f"no SDL role for groups {', '.join(identity.groups) or '(none)'}",
                client,
                outcome=Outcome.DENIED,
                count=False,
                public="your account has not been given access to SDL",
            )
        pending = set()
        if idp.login == "password" and idp.config.require_totp and self.users is not None:
            if record is not None and record.totp_secret is not None:
                await self._need_code(name, provider, record.totp_secret, code, client)
            else:
                pending.add(PENDING_MFA)
        if self.users is not None and (record is not None or idp.config.provision):
            new = record is None
            record = record or UserRecord(name=name, source=provider)
            record.display_name = identity.display_name or record.display_name
            record.email = identity.email or record.email
            record.external_groups = sorted(identity.groups)
            record.last_login = utcnow()
            await self.users.put_user(record)
            if new:
                await self.audit.record(
                    "user.provision",
                    Outcome.SUCCESS,
                    actor=Actor(type=ActorType.USER, id=name),
                    module=provider,
                    message=f"user {name} added on first sign-in through {provider}",
                    user=name,
                    source=provider,
                )
        session = Session(
            name=name,
            kind=SessionKind.PROVIDER,
            provider=provider,
            display_name=identity.display_name,
            expires=0,
            last_seen=0,
            external_groups=list(identity.groups),
            pending=pending,
        )
        return await self._open(session, client, mfa=PENDING_MFA not in pending and bool(code))

    def _superuser_mtime(self) -> float | None:
        path = self.settings.superuser_file
        try:
            return path.stat().st_mtime if path else None
        except OSError:
            return None

    async def _open(self, session: Session, client: str | None, *, mfa: bool) -> LoginResult:
        now = time.time()
        session.created = session.last_seen = now
        session.expires = now + self.settings.session_ttl
        token = SESSION_PREFIX + secrets.token_urlsafe(32)
        actor = await self._actor(session)
        if actor is None:
            raise AuthenticationError("this account cannot sign in")
        async with self._lock:
            self._prune(now)
            self._sessions[_hash(token)] = session
        await self.audit.record(
            "auth.login",
            Outcome.SUCCESS,
            actor=actor,
            module=session.provider if session.kind == SessionKind.PROVIDER else None,
            message=f"signed in with {session.provider}",
            provider=session.provider,
            mfa=mfa,
            pending=sorted(session.pending) or None,
            client=client,
        )
        return LoginResult(
            token=token,
            expires_at=_ts(session.expires),
            actor=actor,
            pending=sorted(session.pending),
        )

    def _prune(self, now: float) -> None:
        for key in [k for k, s in self._sessions.items() if not self._alive(s, now)]:
            del self._sessions[key]
        for key in [k for k, p in self._sso.items() if p.expires < now]:
            del self._sso[key]
        for key in [k for k, (_, exp) in self._codes.items() if exp < now]:
            del self._codes[key]

    def _alive(self, session: Session, now: float) -> bool:
        return session.expires > now and now - session.last_seen < self.settings.session_idle

    # -- single sign-on --------------------------------------------------------------

    def _redirect_provider(self, provider_id: str) -> IdentityProviderModule:
        idp = self.providers.get(provider_id)
        if idp is None or idp.login != "redirect":
            raise NotFoundError(f"no single sign-on provider named {provider_id!r}")
        return idp

    async def sso_begin(self, provider_id: str, callback_url: str, return_to: str) -> str:
        idp = self._redirect_provider(provider_id)
        key = secrets.token_urlsafe(32)
        try:
            start = await idp.begin(callback_url, key)
        except Exception as exc:
            log.exception("identity provider %s failed to start a sign-in", provider_id)
            raise ProviderUnavailableError(
                f"{idp.display_name} could not be reached; try again later"
            ) from exc
        now = time.time()
        async with self._lock:
            self._prune(now)
            if len(self._sso) >= MAX_PENDING_SSO:
                raise ProviderUnavailableError("too many sign-ins in progress; try again shortly")
            self._sso[key] = _Pending(provider_id, start.state, return_to, now + SSO_STATE_TTL)
        return start.url

    async def sso_complete(
        self, provider_id: str, params: dict[str, str], callback_url: str, client: str | None
    ) -> tuple[str, str]:
        """Finish a single sign-on; return a one-time code for the page and where it goes."""
        idp = self._redirect_provider(provider_id)
        key = params.get("state") or params.get("RelayState") or ""
        async with self._lock:
            pending = self._sso.pop(key, None)
        if pending is None or pending.provider != provider_id or pending.expires < time.time():
            raise await self._refuse(
                "-",
                provider_id,
                "single sign-on answer with an unknown or expired state",
                client,
                count=False,
                public="this sign-in link has expired; start again",
            )
        try:
            identity = await idp.complete(params, pending.state, callback_url)
        except ModuleError as exc:
            raise await self._refuse(
                "-",
                provider_id,
                f"single sign-on failed: {exc}",
                client,
                count=False,
                public=f"sign-in with {idp.display_name} failed: {exc}",
            ) from exc
        except Exception as exc:
            log.exception("identity provider %s failed to finish a sign-in", provider_id)
            raise await self._refuse(
                "-",
                provider_id,
                f"single sign-on failed: {exc}",
                client,
                count=False,
                public=f"sign-in with {idp.display_name} failed",
            ) from exc
        result = await self._login_external(idp, identity, client)
        code = secrets.token_urlsafe(32)
        async with self._lock:
            self._codes[_hash(code)] = (result.token, time.time() + SSO_CODE_TTL)
        return code, pending.return_to

    async def exchange(self, code: str) -> LoginResult:
        """Trade the one-time code from a single sign-on for the session token."""
        async with self._lock:
            entry = self._codes.pop(_hash(code), None)
        if entry is None or entry[1] < time.time():
            raise AuthenticationError("this sign-in code has expired; sign in again")
        token = entry[0]
        session = self._sessions.get(_hash(token))
        actor = await self._actor(session) if session else None
        if session is None or actor is None:
            raise AuthenticationError("this sign-in has ended; sign in again")
        return LoginResult(
            token=token,
            expires_at=_ts(session.expires),
            actor=actor,
            pending=sorted(session.pending),
        )

    # -- requests --------------------------------------------------------------------

    async def authenticate(self, request: Request) -> Actor | None:
        """Return the caller of an API request, from a session token or an API token."""
        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        token = token.strip()
        if scheme.lower() == "bearer" and token.startswith(SESSION_PREFIX):
            key = _hash(token)
            session = self._sessions.get(key)
            if session is None:
                return None
            now = time.time()
            if not self._alive(session, now):
                self._sessions.pop(key, None)
                return None
            actor = await self._actor(session)
            if actor is None:
                self._sessions.pop(key, None)
                return None
            session.last_seen = now
            request.state.session_key = key
            return actor
        for module in self.auth_modules:
            actor = await module.authenticate(request)
            if actor is not None:
                return actor
        return None

    async def _actor(self, session: Session) -> Actor | None:
        """The session's user as of now, or None when they may no longer sign in."""
        if session.kind == SessionKind.SUPERUSER:
            if self._superuser_mtime() != session.superuser_mtime:
                return None  # the superuser file was changed or removed: sign in again
            return Actor(
                type=ActorType.USER,
                id=session.name,
                display_name=session.display_name,
                roles=[SUPERUSER_ROLE],
            )
        record = await self.users.get_user(session.name) if self.users else None
        if session.kind == SessionKind.LOCAL:
            if record is None or not record.local or not record.enabled:
                return None
            roles, access = list(record.roles), record.access
        else:
            idp = self.providers.get(session.provider)
            if idp is None:
                return None
            if record is not None and (record.source != session.provider or not record.enabled):
                return None
            roles, access = self._mapped(idp, session.external_groups, record)
            if not roles:
                return None
        return Actor(
            type=ActorType.USER,
            id=session.name,
            display_name=(record.display_name if record else None) or session.display_name,
            roles=[] if session.pending else roles,
            access=access,
        )

    def session_of(self, request: Request) -> Session | None:
        key = getattr(request.state, "session_key", None)
        return self._sessions.get(key) if key else None

    async def me(self, actor: Actor, request: Request) -> Me:
        session = self.session_of(request)
        record = None
        if session is not None and session.kind != SessionKind.SUPERUSER and self.users:
            record = await self.users.get_user(session.name)
        su_mfa = False
        if session is not None and session.kind == SessionKind.SUPERUSER:
            su = self._superuser()
            su_mfa = bool(su and su.totp_secret)
        return Me(
            actor=actor,
            permissions=sorted(permissions_of(actor)),
            access=actor.access,
            signed_in_with=session.provider if session else None,
            pending=sorted(session.pending) if session else [],
            can_change_password=bool(session and session.kind == SessionKind.LOCAL),
            mfa=su_mfa or bool(record and record.mfa),
            session_expires_at=_ts(session.expires) if session else None,
        )

    async def logout(self, actor: Actor, request: Request) -> None:
        key = getattr(request.state, "session_key", None)
        if key:
            self._sessions.pop(key, None)
            await self.audit.record("auth.logout", Outcome.SUCCESS, actor=actor)

    def revoke(self, name: str, keep: str | None = None) -> int:
        """End every session of the user (but ``keep``); return how many ended."""
        keys = [k for k, s in self._sessions.items() if s.name == name and k != keep]
        for key in keys:
            del self._sessions[key]
        return len(keys)

    # -- self service ----------------------------------------------------------------

    def _own_record_session(self, request: Request, *, local: bool) -> Session:
        session = self.session_of(request)
        if session is None or session.kind == SessionKind.SUPERUSER or self.users is None:
            raise RequestError(
                "only users kept by SDL can do this here; the superuser uses 'sdl superuser set'"
            )
        if local and session.kind != SessionKind.LOCAL:
            raise RequestError(f"your password is managed by {session.provider}")
        return session

    async def change_own_password(
        self, actor: Actor, request: Request, current: str, new: str
    ) -> None:
        session = self._own_record_session(request, local=True)
        assert self.users is not None
        record = await self.users.get_user(session.name)
        if record is None:
            raise NotFoundError("your account no longer exists")
        if not await asyncio.to_thread(passwords.verify_password, record.password_hash, current):
            await self.audit.record(
                "user.password.change",
                Outcome.FAILURE,
                actor=actor,
                module=self.users.instance_id,
                message="wrong current password",
                user=record.name,
            )
            raise ForbiddenError("the current password is wrong")
        if new == current:
            raise RequestError("the new password must differ from the current one")
        self._policy(new, record.name)
        record.password_hash = await asyncio.to_thread(passwords.hash_password, new)
        record.password_changed_at = record.updated_at = utcnow()
        record.must_change_password = False
        await self.users.put_user(record)
        session.pending.discard(PENDING_PASSWORD)
        ended = self.revoke(record.name, keep=request.state.session_key)
        await self.audit.record(
            "user.password.change",
            Outcome.SUCCESS,
            actor=actor,
            module=self.users.instance_id,
            message=f"{record.name} changed their password",
            user=record.name,
            sessions_ended=ended,
        )

    async def begin_totp(self, actor: Actor, request: Request) -> TotpEnrollment:
        session = self._own_record_session(request, local=False)
        if session.kind == SessionKind.PROVIDER:
            idp = self.providers.get(session.provider)
            if idp is None or idp.login != "password":
                raise RequestError(f"multi-factor sign-in is managed by {session.provider}")
        assert self.users is not None
        record = await self.users.get_user(session.name)
        if record is None:
            raise NotFoundError("your account is not kept by SDL")
        if record.mfa:
            raise ConflictError(
                "an authenticator is already set up; ask an administrator to reset it"
            )
        secret = totp.new_secret()
        self._totp_enroll[record.name] = (secret, time.time() + TOTP_ENROLL_TTL)
        return TotpEnrollment(secret=secret, uri=totp.provisioning_uri(secret, record.name))

    async def confirm_totp(self, actor: Actor, request: Request, code: str) -> None:
        session = self._own_record_session(request, local=False)
        assert self.users is not None
        secret, expires = self._totp_enroll.get(session.name, ("", 0.0))
        if not secret or expires < time.time():
            raise RequestError("start setting up the authenticator again")
        step = totp.verify(secret, code)
        if step is None:
            raise RequestError("that code is not right; check the device's clock and try again")
        record = await self.users.get_user(session.name)
        if record is None:
            raise NotFoundError("your account no longer exists")
        record.totp_secret = SecretStr(secret)
        record.updated_at = utcnow()
        await self.users.put_user(record)
        del self._totp_enroll[session.name]
        self._totp_last[f"{session.provider}:{session.name}"] = step
        session.pending.discard(PENDING_MFA)
        await self.audit.record(
            "user.mfa.enroll",
            Outcome.SUCCESS,
            actor=actor,
            module=self.users.instance_id,
            message=f"{record.name} set up a TOTP authenticator",
            user=record.name,
        )

    # -- user management -------------------------------------------------------------

    def _store(self) -> UserStoreModule:
        if self.users is None:
            raise RequestError("no user-store module is configured")
        return self.users

    @staticmethod
    def _can_manage(actor: Actor) -> None:
        if actor.access is not None and not actor.access.all_systems:
            raise ForbiddenError(
                "only users who reach every system can manage users "
                "(otherwise they could widen their own access)"
            )

    def _policy(self, password: str, name: str) -> None:
        try:
            passwords.check_policy(password, self.settings.password_min_length, name=name)
        except passwords.PasswordPolicyError as exc:
            raise RequestError(str(exc)) from exc

    def _superuser_name(self) -> str | None:
        su = self._superuser()
        return su.name if su else None

    async def list_users(self) -> list[UserView]:
        users = await self._store().list_users()
        return [UserView.of(u) for u in sorted(users, key=lambda u: u.name)]

    async def get_user(self, name: str) -> UserView:
        user = await self._store().get_user(name)
        if user is None:
            raise NotFoundError(f"no user named {name!r}")
        return UserView.of(user)

    async def create_user(self, actor: Actor, body: UserCreate) -> UserView:
        self._can_manage(actor)
        store = self._store()
        try:
            check_roles(body.roles)
            user = UserRecord(
                name=body.name,
                display_name=body.display_name,
                email=body.email,
                roles=sorted(set(body.roles)),
                access=body.access,
                enabled=body.enabled,
            )
        except ValueError as exc:
            raise RequestError(str(exc)) from exc
        if user.name == self._superuser_name():
            raise ConflictError(f"{user.name!r} is the superuser's name")
        if await store.get_user(user.name) is not None:
            raise ConflictError(f"a user named {user.name!r} already exists")
        if body.password is not None:
            password = body.password.get_secret_value()
            self._policy(password, user.name)
            user.password_hash = await asyncio.to_thread(passwords.hash_password, password)
            user.password_changed_at = utcnow()
            user.must_change_password = True
        await self._write(
            actor,
            "user.create",
            user,
            details={
                "roles": user.roles,
                "access": user.access.model_dump(),
                "enabled": user.enabled,
            },
        )
        return UserView.of(user)

    async def update_user(self, actor: Actor, name: str, body: UserUpdate) -> UserView:
        self._can_manage(actor)
        store = self._store()
        user = await store.get_user(name)
        if user is None:
            raise NotFoundError(f"no user named {name!r}")
        before = UserView.of(user).model_dump(mode="json")
        if body.roles is not None:
            try:
                check_roles(body.roles)
            except ValueError as exc:
                raise RequestError(str(exc)) from exc
            user.roles = sorted(set(body.roles))
        if body.access is not None:
            user.access = body.access
        if body.enabled is not None:
            user.enabled = body.enabled
        for attr in ("display_name", "email"):
            if attr in body.model_fields_set:
                setattr(user, attr, getattr(body, attr) or None)
        after = UserView.of(user).model_dump(mode="json")
        changes = {
            k: {"from": before[k], "to": after[k]}
            for k in ("display_name", "email", "roles", "access", "enabled")
            if before[k] != after[k]
        }
        if not changes:
            return UserView.of(user)
        user.updated_at = utcnow()
        ended = self.revoke(user.name) if body.enabled is False else 0
        details = {"changes": changes, "sessions_ended": ended or None}
        await self._write(actor, "user.update", user, details=details)
        return UserView.of(user)

    async def delete_user(self, actor: Actor, name: str) -> None:
        self._can_manage(actor)
        store = self._store()
        name = name.lower()
        if not await store.delete_user(name):
            raise NotFoundError(f"no user named {name!r}")
        ended = self.revoke(name)
        await self.audit.record(
            "user.delete",
            Outcome.SUCCESS,
            actor=actor,
            module=store.instance_id,
            message=f"user {name} removed",
            user=name,
            sessions_ended=ended,
        )

    async def set_password(self, actor: Actor, name: str, password: str, temporary: bool) -> None:
        self._can_manage(actor)
        store = self._store()
        user = await store.get_user(name)
        if user is None:
            raise NotFoundError(f"no user named {name!r}")
        if not user.local:
            raise RequestError(f"{user.name}'s password is managed by {user.source}")
        self._policy(password, user.name)
        user.password_hash = await asyncio.to_thread(passwords.hash_password, password)
        user.password_changed_at = user.updated_at = utcnow()
        user.must_change_password = temporary
        ended = self.revoke(user.name)
        self._clear_failures(f"{LOCAL_SOURCE}:{user.name}")
        details = {"temporary": temporary, "sessions_ended": ended}
        await self._write(actor, "user.password.reset", user, details=details)

    async def reset_mfa(self, actor: Actor, name: str) -> None:
        self._can_manage(actor)
        store = self._store()
        user = await store.get_user(name)
        if user is None:
            raise NotFoundError(f"no user named {name!r}")
        if user.totp_secret is None:
            raise RequestError(f"{user.name} has no authenticator set up")
        user.totp_secret = None
        user.updated_at = utcnow()
        ended = self.revoke(user.name)
        await self._write(actor, "user.mfa.reset", user, details={"sessions_ended": ended})

    async def unlock(self, actor: Actor, name: str) -> None:
        self._can_manage(actor)
        name = name.lower()
        keys = [k for k in self._failures if k.split("|", 1)[0].split(":", 1)[1] == name]
        for key in keys:
            del self._failures[key]
        await self.audit.record(
            "user.unlock", Outcome.SUCCESS, actor=actor, message=f"user {name} unlocked", user=name
        )

    async def _write(
        self, actor: Actor, action: str, user: UserRecord, details: dict[str, Any]
    ) -> None:
        store = self._store()
        verb = {
            "user.create": "added",
            "user.update": "changed",
            "user.import": "added",
            "user.password.reset": "password reset",
            "user.mfa.reset": "authenticator reset",
        }.get(action, action)
        try:
            await store.put_user(user)
        except Exception as exc:
            await self.audit.record(
                action,
                Outcome.FAILURE,
                actor=actor,
                module=store.instance_id,
                message=str(exc) or type(exc).__name__,
                user=user.name,
            )
            raise
        await self.audit.record(
            action,
            Outcome.SUCCESS,
            actor=actor,
            module=store.instance_id,
            message=f"user {user.name} {verb}",
            user=user.name,
            source=user.source,
            **{k: v for k, v in details.items() if v is not None},
        )

    # -- directories -------------------------------------------------------------------

    def provider(self, provider_id: str) -> IdentityProviderModule:
        idp = self.providers.get(provider_id)
        if idp is None:
            raise NotFoundError(f"no identity provider named {provider_id!r}")
        return idp

    async def search_directory(
        self, actor: Actor, provider_id: str, query: str, limit: int
    ) -> list[ExternalIdentity]:
        self._can_manage(actor)
        idp = self.provider(provider_id)
        if not idp.can_search:
            raise RequestError(f"{idp.display_name} cannot list its users")
        try:
            return await idp.search_users(query, limit)
        except Exception as exc:
            raise ProviderUnavailableError(f"{idp.display_name}: {exc}") from exc

    async def import_user(
        self,
        actor: Actor,
        provider_id: str,
        username: str,
        roles: list[str],
        access: Access,
    ) -> UserView:
        """Add a directory user to SDL ahead of their first sign-in, with what they are assigned."""
        self._can_manage(actor)
        store = self._store()
        idp = self.provider(provider_id)
        username = username.strip().lower()
        if idp.can_search:
            found = [u for u in await self.search_directory(actor, provider_id, username, 50)]
            match = next((u for u in found if u.username == username), None)
            if match is None:
                raise NotFoundError(f"{idp.display_name} has no user named {username!r}")
        else:
            match = ExternalIdentity(username=username)
        try:
            check_roles(roles)
            user = UserRecord(
                name=match.username,
                display_name=match.display_name,
                email=match.email,
                source=provider_id,
                roles=sorted(set(roles)),
                access=access,
                external_groups=sorted(match.groups),
            )
        except ValueError as exc:
            raise RequestError(str(exc)) from exc
        if user.name == self._superuser_name():
            raise ConflictError(f"{user.name!r} is the superuser's name")
        if await store.get_user(user.name) is not None:
            raise ConflictError(f"a user named {user.name!r} already exists")
        await self._write(
            actor,
            "user.import",
            user,
            details={"roles": user.roles, "access": user.access.model_dump()},
        )
        return UserView.of(user)
