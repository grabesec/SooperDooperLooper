"""OpenID Connect single sign-on: Microsoft Entra ID, Okta, Keycloak, Google, Auth0...

The browser is sent to the provider's sign-in page (authorization code flow
with PKCE, ``state`` and ``nonce``); the provider sends it back to SDL with a
code, which SDL trades for an ID token. SDL checks the token's signature
against the provider's published keys, its issuer, audience, expiry and nonce,
then reads the user name and groups from its claims. The core maps groups to
SDL roles, inventory groups and systems (``group_mapping``).

Entra ID: ``issuer: https://login.microsoftonline.com/<tenant id>/v2.0``; add
the ``groups`` claim (group object ids) or app roles (``groups_claim: roles``)
to the app registration's token configuration.

Needs PyJWT with cryptography: ``pip install 'sooperdooperlooper[oidc]'``.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import time
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlencode

import httpx
from pydantic import Field

from sdl.core.models import ExternalIdentity
from sdl.core.module import IdentityProviderModule, IdpConfig, ModuleError, SsoStart

DISCOVERY_TTL = 3600.0


class OidcConfig(IdpConfig):
    issuer: str = Field(description="Issuer URL; its /.well-known/openid-configuration is read.")
    client_id: str
    client_secret_env: str | None = Field(
        default=None,
        description="Environment variable holding the client secret; unset for a public "
        "client (PKCE only).",
    )
    token_auth: Literal["client_secret_basic", "client_secret_post"] = "client_secret_basic"  # noqa: S105
    scopes: list[str] = Field(default_factory=lambda: ["openid", "profile", "email"])
    username_claim: str = Field(
        default="preferred_username",
        description="Claim used as the SDL user name (Entra ID: preferred_username or upn).",
    )
    display_name_claim: str = "name"
    email_claim: str = "email"
    groups_claim: str = Field(
        default="groups", description="Claim listing the user's groups (Entra ID: groups or roles)."
    )
    userinfo: bool = Field(
        default=False, description="Also read claims from the userinfo endpoint."
    )
    algorithms: list[str] = Field(
        default_factory=lambda: ["RS256", "RS384", "RS512", "PS256", "ES256", "ES384"]
    )
    extra_params: dict[str, str] = Field(
        default_factory=dict,
        description="Extra sign-in URL parameters, e.g. {prompt: select_account}.",
    )
    ca_cert: Path | None = None
    timeout: float = Field(default=10, gt=0)
    leeway: float = Field(default=60, ge=0, description="Clock skew allowed, in seconds.")


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge.decode().rstrip("=")


class OidcIdentityProvider(IdentityProviderModule):
    Config = OidcConfig
    description = "Single sign-on with OpenID Connect (Entra ID, Okta, Keycloak, Google...)."
    config: OidcConfig
    login = "redirect"

    def __init__(self, config: Any, context: Any) -> None:
        super().__init__(config, context)
        self._discovery: dict[str, Any] | None = None
        self._discovered_at = 0.0
        self._jwks: dict[str, Any] | None = None
        self._transport: httpx.AsyncBaseTransport | None = None  # tests inject a mock

    async def start(self) -> None:
        try:
            import jwt  # noqa: F401
        except ImportError as exc:  # pragma: no cover - depends on the installation
            raise ModuleError("PyJWT is needed: pip install 'sooperdooperlooper[oidc]'") from exc
        if self.config.client_secret_env and not os.environ.get(self.config.client_secret_env):
            raise ModuleError(f"environment variable {self.config.client_secret_env} is not set")

    async def health(self) -> dict[str, Any]:
        try:
            await self._discover()
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True}

    def _client(self) -> httpx.AsyncClient:
        verify: Any = str(self.config.ca_cert) if self.config.ca_cert else True
        return httpx.AsyncClient(
            timeout=self.config.timeout, verify=verify, transport=self._transport
        )

    async def _get_json(self, url: str, **kwargs: Any) -> dict[str, Any]:
        try:
            async with self._client() as client:
                response = await client.get(url, **kwargs)
                response.raise_for_status()
                data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ModuleError(f"cannot read {url}: {exc}") from exc
        if not isinstance(data, dict):
            raise ModuleError(f"{url} did not return a JSON object")
        return data

    async def _discover(self) -> dict[str, Any]:
        if self._discovery is None or time.time() - self._discovered_at > DISCOVERY_TTL:
            url = self.config.issuer.rstrip("/") + "/.well-known/openid-configuration"
            data = await self._get_json(url)
            for key in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
                if not isinstance(data.get(key), str):
                    raise ModuleError(f"the provider's discovery document has no {key}")
            if data["issuer"].rstrip("/") != self.config.issuer.rstrip("/"):
                raise ModuleError(
                    f"the provider says its issuer is {data['issuer']!r}, "
                    f"not {self.config.issuer!r}"
                )
            self._discovery, self._discovered_at = data, time.time()
            self._jwks = None
        return self._discovery

    async def begin(self, callback_url: str, state: str) -> SsoStart:
        discovery = await self._discover()
        verifier, challenge = _pkce()
        nonce = secrets.token_urlsafe(24)
        params = {
            **self.config.extra_params,
            "response_type": "code",
            "client_id": self.config.client_id,
            "redirect_uri": callback_url,
            "scope": " ".join(self.config.scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        separator = "&" if "?" in discovery["authorization_endpoint"] else "?"
        return SsoStart(
            url=discovery["authorization_endpoint"] + separator + urlencode(params),
            state={"verifier": verifier, "nonce": nonce},
        )

    async def complete(
        self, params: dict[str, str], state: dict[str, Any], callback_url: str
    ) -> ExternalIdentity:
        if params.get("error"):
            detail = params.get("error_description") or params["error"]
            raise ModuleError(f"the provider refused the sign-in: {detail}")
        code = params.get("code")
        if not code:
            raise ModuleError("the provider sent no authorization code")
        discovery = await self._discover()
        tokens = await self._token(discovery, code, state["verifier"], callback_url)
        id_token = tokens.get("id_token")
        if not isinstance(id_token, str):
            raise ModuleError("the provider sent no ID token")
        claims = await self._verify(discovery, id_token, state["nonce"])
        if self.config.userinfo and discovery.get("userinfo_endpoint"):
            access = tokens.get("access_token")
            info = await self._get_json(
                discovery["userinfo_endpoint"], headers={"Authorization": f"Bearer {access}"}
            )
            if info.get("sub") != claims.get("sub"):
                raise ModuleError("userinfo is about a different user than the ID token")
            claims = {**info, **claims}
        return self._identity(claims)

    async def _token(
        self, discovery: dict[str, Any], code: str, verifier: str, callback_url: str
    ) -> dict[str, Any]:
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": callback_url,
            "code_verifier": verifier,
            "client_id": self.config.client_id,
        }
        auth: tuple[str | bytes, str | bytes] | None = None
        secret = os.environ.get(self.config.client_secret_env or "", "")
        if self.config.client_secret_env:
            if self.config.token_auth == "client_secret_basic":  # noqa: S105
                auth = (self.config.client_id, secret)
            else:
                form["client_secret"] = secret
        try:
            async with self._client() as client:
                response = await client.post(
                    discovery["token_endpoint"], data=form, auth=auth or httpx.USE_CLIENT_DEFAULT
                )
                data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ModuleError(f"cannot redeem the authorization code: {exc}") from exc
        if response.status_code >= 400 or not isinstance(data, dict):
            detail = (
                data.get("error_description") or data.get("error")
                if isinstance(data, dict)
                else None
            )
            raise ModuleError(
                f"the provider refused the authorization code: {detail or response.status_code}"
            )
        return data

    async def _key(self, discovery: dict[str, Any], kid: str | None) -> Any:
        import jwt

        for attempt in range(2):
            if self._jwks is None or attempt:
                self._jwks = await self._get_json(discovery["jwks_uri"])
            try:
                keys = jwt.PyJWKSet.from_dict(self._jwks)
            except jwt.PyJWTError as exc:
                raise ModuleError(f"cannot read the provider's signing keys: {exc}") from exc
            for key in keys.keys:
                if kid is None or key.key_id == kid:
                    return key.key
        raise ModuleError("the ID token is signed with a key the provider does not publish")

    async def _verify(self, discovery: dict[str, Any], id_token: str, nonce: str) -> dict[str, Any]:
        import jwt

        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as exc:
            raise ModuleError(f"the ID token is malformed: {exc}") from exc
        if header.get("alg") not in self.config.algorithms:
            raise ModuleError(f"the ID token uses a refused algorithm: {header.get('alg')}")
        key = await self._key(discovery, header.get("kid"))
        try:
            claims: dict[str, Any] = jwt.decode(
                id_token,
                key,
                algorithms=self.config.algorithms,
                audience=self.config.client_id,
                issuer=discovery["issuer"],
                leeway=self.config.leeway,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise ModuleError(f"the ID token is not valid: {exc}") from exc
        if claims.get("nonce") != nonce:
            raise ModuleError("the ID token's nonce does not match this sign-in")
        audience = claims.get("aud")
        if (
            isinstance(audience, list)
            and len(audience) > 1
            and claims.get("azp") != self.config.client_id
        ):
            raise ModuleError("the ID token was issued to another client")
        return claims

    def _identity(self, claims: dict[str, Any]) -> ExternalIdentity:
        username = claims.get(self.config.username_claim)
        if not isinstance(username, str) or not username:
            raise ModuleError(f"the ID token has no {self.config.username_claim!r} claim")
        if self.config.username_claim == "email" and claims.get("email_verified") is not True:
            raise ModuleError("the provider has not verified this email address")
        groups = claims.get(self.config.groups_claim) or []
        if isinstance(groups, str):
            groups = [groups]
        if not isinstance(groups, list):
            raise ModuleError(f"the {self.config.groups_claim!r} claim is not a list")
        if "_claim_names" in claims and self.config.groups_claim in claims["_claim_names"]:
            raise ModuleError(
                "the provider left the groups out of the token (too many groups); "
                "map app roles instead (groups_claim: roles)"
            )
        display = claims.get(self.config.display_name_claim)
        email = claims.get(self.config.email_claim)
        return ExternalIdentity(
            username=username,
            display_name=display if isinstance(display, str) else None,
            email=email if isinstance(email, str) else None,
            groups=[str(g) for g in groups],
        )
