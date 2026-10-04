"""LDAP and Active Directory sign-in.

Users type their directory user name and password into SDL's sign-in form.
The module looks the user up with a search account, then binds as the user
to check the password, and reads the groups the user belongs to. The core
maps those groups to SDL roles, inventory groups and systems
(``group_mapping``).

``directory: active_directory`` fills in Active Directory's attribute names
and follows nested group membership. Passwords are only ever sent over TLS
(``ldaps://`` or StartTLS) unless ``allow_insecure`` is set, for test labs.

Needs the ``ldap3`` package: ``pip install 'sooperdooperlooper[ldap]'``.
"""

from __future__ import annotations

import asyncio
import os
import ssl
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from pydantic import Field, model_validator

from sdl.core.models import ExternalIdentity
from sdl.core.module import IdentityProviderModule, IdpConfig, ModuleError

if TYPE_CHECKING:
    from ldap3 import Connection, Server

AD_NESTED_MATCH = "1.2.840.113556.1.4.1941"
"""LDAP_MATCHING_RULE_IN_CHAIN: Active Directory's rule for transitive group membership."""

DEFAULTS: dict[str, dict[str, Any]] = {
    "generic": {
        "user_filter": "(&(objectClass=person)(uid={username}))",
        "username_attribute": "uid",
        "display_name_attribute": "cn",
        "group_filter": "(|(member={user_dn})(uniqueMember={user_dn}))",
    },
    "active_directory": {
        "user_filter": "(&(objectCategory=person)(objectClass=user)(sAMAccountName={username}))",
        "username_attribute": "sAMAccountName",
        "display_name_attribute": "displayName",
        "group_filter": f"(member:{AD_NESTED_MATCH}:={{user_dn}})",
    },
}


class LdapConfig(IdpConfig):
    directory: Literal["generic", "active_directory"] = "generic"
    urls: list[str] = Field(
        min_length=1,
        description="Directory servers, tried in order: ldaps://dc1.example.com, ...",
    )
    start_tls: bool = Field(default=False, description="Upgrade ldap:// connections with StartTLS.")
    ca_cert: Path | None = Field(
        default=None, description="CA bundle for the directory's certificate; system CAs if unset."
    )
    allow_insecure: bool = Field(
        default=False,
        description="Allow sending passwords without TLS (plain ldap:// without StartTLS). "
        "Only for test labs.",
    )
    bind_dn: str | None = Field(
        default=None,
        description="Search account's DN (or user@domain for AD); anonymous search when unset.",
    )
    bind_password_env: str | None = Field(
        default=None, description="Environment variable holding the search account's password."
    )
    user_base_dn: str = Field(description="Where users are searched, e.g. dc=example,dc=com.")
    user_filter: str | None = Field(
        default=None, description="Filter finding one user; {username} is replaced (escaped)."
    )
    username_attribute: str | None = None
    display_name_attribute: str | None = None
    email_attribute: str = "mail"
    group_base_dn: str | None = Field(
        default=None,
        description="Where groups are searched; when unset, groups come from the user's "
        "memberOf attribute (direct membership only).",
    )
    group_filter: str | None = Field(
        default=None, description="Filter for the user's groups; {user_dn} is replaced."
    )
    group_name: Literal["cn", "dn"] = Field(
        default="cn", description="Map groups by their common name or full DN."
    )
    timeout: float = Field(default=10, gt=0)

    @model_validator(mode="after")
    def _defaults(self) -> LdapConfig:
        for key, value in DEFAULTS[self.directory].items():
            if getattr(self, key) is None:
                setattr(self, key, value)
        if "{username}" not in (self.user_filter or ""):
            raise ValueError("user_filter must contain {username}")
        insecure = [u for u in self.urls if not u.lower().startswith("ldaps://")]
        if insecure and not self.start_tls and not self.allow_insecure:
            raise ValueError(
                "passwords would cross the network unencrypted: use ldaps:// URLs or "
                "start_tls: true (or allow_insecure: true in a test lab)"
            )
        return self


def _escape(value: str) -> str:
    from ldap3.utils.conv import escape_filter_chars

    return str(escape_filter_chars(value))


def _first(entry: Any, attribute: str | None) -> str | None:
    if not attribute:
        return None
    values = entry.get("attributes", {}).get(attribute)
    if isinstance(values, list):
        return str(values[0]) if values else None
    return str(values) if values not in (None, "") else None


def _cn(dn: str) -> str:
    try:
        from ldap3.utils.dn import parse_dn

        key, value, _ = parse_dn(dn, escape=False, strip=True)[0]
    except Exception:  # not a parseable DN: match it as a whole
        return dn
    return value if key.strip().lower() == "cn" and value else dn


class LdapIdentityProvider(IdentityProviderModule):
    Config = LdapConfig
    description = "Sign in with an LDAP or Active Directory account; groups map to SDL access."
    config: LdapConfig
    login = "password"
    can_search = True
    _client_strategy: str | None = None  # the tests use ldap3's in-memory MOCK_SYNC

    async def start(self) -> None:
        try:
            import ldap3  # noqa: F401
        except ImportError as exc:  # pragma: no cover - depends on the installation
            raise ModuleError(
                "the ldap3 package is needed: pip install 'sooperdooperlooper[ldap]'"
            ) from exc
        if self.config.bind_password_env and not os.environ.get(self.config.bind_password_env):
            raise ModuleError(f"environment variable {self.config.bind_password_env} is not set")

    async def health(self) -> dict[str, Any]:
        try:
            await asyncio.to_thread(self._service_connection)
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True}

    # Overridden by the tests, which use ldap3's in-memory mock directory.
    def _server(self) -> Server | list[Server]:
        from ldap3 import Server, ServerPool, Tls

        tls = Tls(
            validate=ssl.CERT_REQUIRED,
            ca_certs_file=str(self.config.ca_cert) if self.config.ca_cert else None,
        )
        servers = [
            Server(
                url,
                use_ssl=url.lower().startswith("ldaps://"),
                tls=tls,
                connect_timeout=self.config.timeout,
            )
            for url in self.config.urls
        ]
        return servers[0] if len(servers) == 1 else ServerPool(servers, active=1, exhaust=True)

    def _connect(self, user: str | None, password: str | None) -> Connection:
        from ldap3 import Connection
        from ldap3.core.exceptions import LDAPException

        conn = Connection(
            self._server(),
            user=user,
            password=password,
            receive_timeout=self.config.timeout,
            raise_exceptions=False,
            read_only=True,
            **({"client_strategy": self._client_strategy} if self._client_strategy else {}),
        )
        try:
            conn.open()
            if self.config.start_tls and not (conn.start_tls() and conn.tls_started):
                raise ModuleError("directory unavailable: StartTLS failed")
            conn.bind()
        except LDAPException as exc:
            raise ModuleError(f"directory unavailable: {exc}") from exc
        return conn

    def _service_connection(self) -> Connection:
        password = None
        if self.config.bind_password_env:
            password = os.environ.get(self.config.bind_password_env)
        conn = self._connect(self.config.bind_dn, password)
        if not conn.bound:
            raise ModuleError(
                f"the search account could not bind: {conn.result.get('description')}"
            )
        return conn

    def _attributes(self) -> list[str]:
        attrs = {
            self.config.username_attribute,
            self.config.display_name_attribute,
            self.config.email_attribute,
        }
        if not self.config.group_base_dn:
            attrs.add("memberOf")
        return [a for a in attrs if a]

    def _identity(self, conn: Connection, entry: Any) -> ExternalIdentity:
        username = _first(entry, self.config.username_attribute)
        if not username:
            raise ModuleError(f"{entry.get('dn')} has no {self.config.username_attribute}")
        return ExternalIdentity(
            username=username,
            display_name=_first(entry, self.config.display_name_attribute),
            email=_first(entry, self.config.email_attribute),
            groups=self._groups(conn, entry),
        )

    def _groups(self, conn: Connection, entry: Any) -> list[str]:
        dn = str(entry["dn"])
        if self.config.group_base_dn and self.config.group_filter:
            group_filter = self.config.group_filter.replace("{user_dn}", _escape(dn))
            conn.search(self.config.group_base_dn, group_filter, attributes=["cn"])
            dns = [str(e["dn"]) for e in conn.response or [] if e.get("type") == "searchResEntry"]
        else:
            values = entry.get("attributes", {}).get("memberOf") or []
            dns = [str(v) for v in (values if isinstance(values, list) else [values])]
        names = dns if self.config.group_name == "dn" else [_cn(d) for d in dns]
        return sorted(set(names))

    def _find(self, conn: Connection, username: str) -> list[Any]:
        assert self.config.user_filter is not None
        user_filter = self.config.user_filter.replace("{username}", _escape(username))
        conn.search(
            self.config.user_base_dn, user_filter, attributes=self._attributes(), size_limit=2
        )
        return [e for e in conn.response or [] if e.get("type") == "searchResEntry"]

    def _authenticate(self, username: str, password: str) -> ExternalIdentity | None:
        conn = self._service_connection()
        try:
            found = self._find(conn, username)
            if len(found) != 1:
                return None
            entry = found[0]
            user_conn = self._connect(str(entry["dn"]), password)
            try:
                if not user_conn.bound:
                    return None
            finally:
                user_conn.unbind()
            return self._identity(conn, entry)
        finally:
            conn.unbind()

    async def authenticate(self, username: str, password: str) -> ExternalIdentity | None:
        if not username or not password:
            return None  # an empty password would be an anonymous bind, which "succeeds"
        return await asyncio.to_thread(self._authenticate, username, password)

    def _search(self, query: str, limit: int) -> list[ExternalIdentity]:
        assert self.config.user_filter is not None
        base = self.config.user_filter.replace("{username}", "*")
        words = "".join(
            f"({a}=*{_escape(query)}*)"
            for a in (
                self.config.username_attribute,
                self.config.display_name_attribute,
                self.config.email_attribute,
            )
            if a
        )
        search_filter = f"(&{base}(|{words}))" if query else base
        conn = self._service_connection()
        try:
            conn.search(
                self.config.user_base_dn,
                search_filter,
                attributes=self._attributes(),
                size_limit=limit,
            )
            entries = [e for e in conn.response or [] if e.get("type") == "searchResEntry"]
            found = []
            for entry in entries[:limit]:
                try:
                    found.append(self._identity(conn, entry))
                except ModuleError:
                    continue
            return found
        finally:
            conn.unbind()

    async def search_users(self, query: str, limit: int = 50) -> list[ExternalIdentity]:
        return await asyncio.to_thread(self._search, query.strip(), limit)
