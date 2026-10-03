from __future__ import annotations

import base64
import datetime as dt
import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from ldap3 import MOCK_SYNC, OFFLINE_SLAPD_2_4, Server
from lxml import etree
from signxml import XMLSigner

from sdl.api.app import create_app
from sdl.core.module import ModuleError
from sdl.modules.idp_ldap import LdapConfig, LdapIdentityProvider
from sdl.modules.idp_oidc import OidcIdentityProvider
from tests.conftest import ADMIN_TOKEN

ISSUER = "https://login.example.com/tenant/v2.0"
CLIENT_ID = "sdl-client"
SP_ENTITY = "https://sdl.example.com/saml"
IDP_ENTITY = "https://idp.example.com/saml"
BASE = "http://testserver"


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# -- LDAP / Active Directory ---------------------------------------------------------------

DIRECTORY = Server("directory", get_info=OFFLINE_SLAPD_2_4)
PEOPLE = "ou=people,dc=example,dc=com"
GROUPS = "ou=groups,dc=example,dc=com"


class MockLdap(LdapIdentityProvider):
    """The real module, against ldap3's in-memory directory."""

    _client_strategy = MOCK_SYNC

    def _server(self) -> Any:
        return DIRECTORY


def _seed_directory() -> None:
    from ldap3 import Connection

    conn = Connection(DIRECTORY, client_strategy=MOCK_SYNC)
    add = conn.strategy.add_entry
    add("cn=sdl-search,dc=example,dc=com", {"userPassword": "search-pw", "objectClass": "person"})
    for uid, name, password, groups in (
        ("alice", "Alice Admin", "alice-pw", ["sdl-admins"]),
        ("olaf", "Olaf Operator", "olaf-pw", ["web-ops"]),
        ("nora", "Nora Nobody", "nora-pw", []),
    ):
        add(
            f"uid={uid},{PEOPLE}",
            {
                "uid": uid,
                "cn": name,
                "mail": f"{uid}@example.com",
                "userPassword": password,
                "objectClass": ["person"],
                "memberOf": [f"cn={g},{GROUPS}" for g in groups],
            },
        )
    for group, members in (("sdl-admins", ["alice"]), ("web-ops", ["olaf"])):
        add(
            f"cn={group},{GROUPS}",
            {
                "cn": group,
                "objectClass": "groupOfNames",
                "member": [f"uid={m},{PEOPLE}" for m in members],
            },
        )


_seed_directory()

LDAP_CONFIG = {
    "urls": ["ldap://directory"],
    "allow_insecure": True,
    "bind_dn": "cn=sdl-search,dc=example,dc=com",
    "bind_password_env": "SDL_TEST_LDAP_PW",
    "user_base_dn": PEOPLE,
    "group_mapping": [
        {"group": "SDL-Admins", "roles": ["admin"], "all_systems": True},
        {"group": "web-ops", "roles": ["operator"], "groups": ["web"]},
    ],
    "display_name": "Example AD",
}


@pytest.fixture(autouse=True)
def _ldap_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SDL_TEST_LDAP_PW", "search-pw")


def ldap_module(**overrides: Any) -> MockLdap:
    from sdl.core.audit import AuditRecorder
    from sdl.core.module import ModuleContext

    config = LdapConfig.model_validate({**LDAP_CONFIG, **overrides})
    return MockLdap(config, ModuleContext("ad", AuditRecorder()))


def test_ldap_config_refuses_plain_text_passwords() -> None:
    with pytest.raises(ValueError, match="unencrypted"):
        LdapConfig.model_validate({**LDAP_CONFIG, "allow_insecure": False})
    LdapConfig.model_validate({**LDAP_CONFIG, "allow_insecure": False, "start_tls": True})
    ad = LdapConfig.model_validate(
        {**LDAP_CONFIG, "directory": "active_directory", "urls": ["ldaps://dc1"]}
    )
    assert "sAMAccountName={username}" in (ad.user_filter or "")
    assert "1.2.840.113556.1.4.1941" in (ad.group_filter or "")


async def test_ldap_checks_passwords_and_reads_groups() -> None:
    module = ldap_module()
    alice = await module.authenticate("Alice", "alice-pw")
    assert alice is not None and alice.username == "alice"
    assert alice.display_name == "Alice Admin" and alice.email == "alice@example.com"
    assert alice.groups == ["sdl-admins"]
    assert await module.authenticate("alice", "wrong") is None
    assert await module.authenticate("alice", "") is None  # no anonymous-bind trick
    assert await module.authenticate("nobody", "x") is None
    assert await module.authenticate("*", "alice-pw") is None  # filter characters are escaped

    by_search = ldap_module(group_base_dn=GROUPS, group_name="dn")
    olaf = await by_search.authenticate("olaf", "olaf-pw")
    assert olaf is not None and olaf.groups == [f"cn=web-ops,{GROUPS}"]


async def test_ldap_directory_search() -> None:
    found = await ldap_module().search_users("Operator")
    assert [u.username for u in found] == ["olaf"] and found[0].groups == ["web-ops"]
    everyone = await ldap_module().search_users("")
    assert len(everyone) == 3


async def test_ldap_search_account_must_work() -> None:
    import os

    os.environ["SDL_TEST_LDAP_PW"] = "wrong"
    with pytest.raises(ModuleError, match="search account"):
        await ldap_module().authenticate("alice", "alice-pw")


@pytest.fixture
def idp_api(orchestrator_factory: Any, tmp_path: Path) -> Iterator[tuple[TestClient, Any]]:
    signer = OidcSigner()
    saml = SamlSigner(tmp_path)
    modules = {
        "users": {"type": "users.store", "config": {"path": str(tmp_path / "users.json")}},
        "ad": {"type": "idp.mock_ldap", "config": LDAP_CONFIG},
        "entra": {
            "type": "idp.oidc",
            "config": {
                "issuer": ISSUER,
                "client_id": CLIENT_ID,
                "client_secret_env": "SDL_TEST_OIDC_SECRET",
                "display_name": "Entra ID",
                "group_mapping": [
                    {"group": "0f8fad5b-d9cb-469f-a165-70867728950e", "roles": ["operator"],
                     "systems": ["vm3"]},
                ],
            },
        },
        "saml": {
            "type": "idp.saml",
            "config": {
                "sp_entity_id": SP_ENTITY,
                "idp_entity_id": IDP_ENTITY,
                "idp_sso_url": "https://idp.example.com/sso",
                "idp_certificates": [str(saml.cert_path)],
                "default_roles": ["auditor"],
            },
        },
    }  # fmt: skip
    orchestrator = orchestrator_factory(extra_modules=modules)
    orchestrator.registry.register("idp.mock_ldap", MockLdap)
    import os

    os.environ["SDL_TEST_OIDC_SECRET"] = "client-secret"
    with TestClient(create_app(orchestrator)) as client:
        oidc = orchestrator.modules["entra"]
        oidc._transport = httpx.MockTransport(signer.handler)
        yield client, {"oidc": signer, "saml": saml, "orchestrator": orchestrator}
    os.environ.pop("SDL_TEST_OIDC_SECRET", None)


def test_ldap_users_sign_in_with_mapped_access(idp_api: tuple[TestClient, Any]) -> None:
    api, _ = idp_api
    providers = {p["id"]: p for p in api.get("/api/v1/auth/providers").json()}
    assert providers["ad"] == {"id": "ad", "name": "Example AD", "type": "idp.mock_ldap",
                               "login": "password"}  # fmt: skip
    assert providers["entra"]["login"] == "redirect"

    olaf = api.post(
        "/api/v1/auth/login", json={"username": "olaf", "password": "olaf-pw", "provider": "ad"}
    ).json()
    me = api.get("/api/v1/me", headers=bearer(olaf["token"])).json()
    assert me["actor"]["roles"] == ["operator"] and me["signed_in_with"] == "ad"
    assert me["access"]["groups"] == ["web"]
    systems = api.get("/api/v1/systems", headers=bearer(olaf["token"])).json()["systems"]
    assert [s["name"] for s in systems] == ["vm1", "vm2"]

    # First sign-in recorded the user, so an administrator can assign more or disable them.
    record = api.get("/api/v1/users/olaf", headers=bearer(ADMIN_TOKEN)).json()
    assert record["source"] == "ad" and record["external_groups"] == ["web-ops"]
    api.patch("/api/v1/users/olaf", json={"access": {"systems": ["vm3"]}},
              headers=bearer(ADMIN_TOKEN))  # fmt: skip
    systems = api.get("/api/v1/systems", headers=bearer(olaf["token"])).json()["systems"]
    assert [s["name"] for s in systems] == ["vm1", "vm2", "vm3"]
    api.patch("/api/v1/users/olaf", json={"enabled": False}, headers=bearer(ADMIN_TOKEN))
    assert api.get("/api/v1/me", headers=bearer(olaf["token"])).status_code == 401

    # Users in no mapped group get nothing.
    nora = api.post(
        "/api/v1/auth/login", json={"username": "nora", "password": "nora-pw", "provider": "ad"}
    )
    assert nora.status_code == 401 and "not been given access" in nora.json()["detail"]
    wrong = api.post(
        "/api/v1/auth/login", json={"username": "alice", "password": "x", "provider": "ad"}
    )
    assert wrong.status_code == 401


def test_directory_search_and_import(idp_api: tuple[TestClient, Any]) -> None:
    api, _ = idp_api
    admin = bearer(ADMIN_TOKEN)
    found = api.get("/api/v1/idps/ad/users?q=nora", headers=admin).json()
    assert [u["username"] for u in found] == ["nora"]
    imported = api.post(
        "/api/v1/idps/ad/users",
        json={"username": "nora", "roles": ["auditor"], "access": {"groups": ["db"]}},
        headers=admin,
    )
    assert imported.status_code == 201, imported.text
    assert imported.json()["source"] == "ad" and imported.json()["display_name"] == "Nora Nobody"
    # Now nora's own SDL assignment lets her in, though her directory groups map to nothing.
    nora = api.post(
        "/api/v1/auth/login", json={"username": "nora", "password": "nora-pw", "provider": "ad"}
    ).json()
    me = api.get("/api/v1/me", headers=bearer(nora["token"])).json()
    assert me["actor"]["roles"] == ["auditor"] and me["access"]["groups"] == ["db"]
    missing = api.post("/api/v1/idps/ad/users", json={"username": "ghost"}, headers=admin)
    assert missing.status_code == 404
    idps = api.get("/api/v1/idps", headers=admin).json()
    assert {p["id"]: p["can_search"] for p in idps} == {"ad": True, "entra": False, "saml": False}


def test_a_directory_user_cannot_take_over_a_local_account(
    idp_api: tuple[TestClient, Any],
) -> None:
    api, _ = idp_api
    api.post(
        "/api/v1/users", json={"name": "olaf", "roles": ["admin"]}, headers=bearer(ADMIN_TOKEN)
    )
    response = api.post(
        "/api/v1/auth/login", json={"username": "olaf", "password": "olaf-pw", "provider": "ad"}
    )
    assert response.status_code == 401 and "already has this name" in response.json()["detail"]


# -- OpenID Connect (Entra ID, ...) -----------------------------------------------------------


class OidcSigner:
    """A fake OpenID provider: discovery, keys, and a token endpoint."""

    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.claims: dict[str, Any] = {}
        self.nonce: str | None = None
        self.token_requests: list[dict[str, list[str]]] = []
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        self.jwks = {"keys": [{**jwk, "kid": "k1", "use": "sig", "alg": "RS256"}]}

    def id_token(self, **overrides: Any) -> str:
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "user-1",
            "iat": now,
            "exp": now + 300,
            "nonce": self.nonce,
            "preferred_username": "Olivia@Example.com",
            "name": "Olivia",
            "email": "olivia@example.com",
            "groups": ["0f8fad5b-d9cb-469f-a165-70867728950e"],
            **self.claims,
            **overrides,
        }
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "k1"})

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": ISSUER,
                    "authorization_endpoint": "https://login.example.com/authorize",
                    "token_endpoint": "https://login.example.com/token",
                    "jwks_uri": "https://login.example.com/keys",
                },
            )
        if path == "/keys":
            return httpx.Response(200, json=self.jwks)
        if path == "/token":
            form = parse_qs(request.content.decode())
            self.token_requests.append(form)
            if form.get("code") != ["good-code"]:
                return httpx.Response(400, json={"error": "invalid_grant"})
            return httpx.Response(200, json={"id_token": self.id_token(), "access_token": "at"})
        return httpx.Response(404)


def sso_start(api: TestClient, provider: str, return_to: str = "ui") -> dict[str, str]:
    response = api.get(
        f"/api/v1/auth/sso/{provider}/start?return_to={return_to}", follow_redirects=False
    )
    assert response.status_code == 303, response.text
    return {k: v[0] for k, v in parse_qs(urlparse(response.headers["location"]).query).items()}


def fragment(response: httpx.Response) -> dict[str, str]:
    assert response.status_code == 303, response.text
    location = response.headers["location"]
    assert location.startswith("/ui/#")
    return {k: v[0] for k, v in parse_qs(location.split("#", 1)[1]).items()}


def test_oidc_single_sign_on(idp_api: tuple[TestClient, Any]) -> None:
    api, ctx = idp_api
    signer: OidcSigner = ctx["oidc"]
    params = sso_start(api, "entra")
    assert params["client_id"] == CLIENT_ID and params["code_challenge_method"] == "S256"
    assert params["redirect_uri"] == f"{BASE}/api/v1/auth/sso/entra/callback"
    signer.nonce = params["nonce"]

    back = api.get(
        "/api/v1/auth/sso/entra/callback",
        params={"code": "good-code", "state": params["state"]},
        follow_redirects=False,
    )
    code = fragment(back)["sso"]
    token_request = signer.token_requests[-1]
    assert token_request["code_verifier"] and token_request["redirect_uri"] == [
        params["redirect_uri"]
    ]
    session = api.post("/api/v1/auth/sso/exchange", json={"code": code}).json()
    me = api.get("/api/v1/me", headers=bearer(session["token"])).json()
    assert me["actor"]["id"] == "olivia@example.com" and me["actor"]["roles"] == ["operator"]
    assert me["access"]["systems"] == ["vm3"]
    # The one-time code and the state are single use.
    assert api.post("/api/v1/auth/sso/exchange", json={"code": code}).status_code == 401
    replay = api.get(
        "/api/v1/auth/sso/entra/callback",
        params={"code": "good-code", "state": params["state"]},
        follow_redirects=False,
    )
    assert "expired" in fragment(replay)["sso_error"]


@pytest.mark.parametrize(
    ("claims", "error"),
    [
        ({"aud": "someone-else"}, "not valid"),
        ({"iss": "https://evil.example.com"}, "not valid"),
        ({"exp": int(time.time()) - 3600}, "not valid"),
        ({"nonce": "replayed"}, "nonce"),
        ({"groups": ["unmapped"]}, "not been given access"),
    ],
)
def test_oidc_refuses_bad_tokens(
    idp_api: tuple[TestClient, Any], claims: dict[str, Any], error: str
) -> None:
    api, ctx = idp_api
    signer: OidcSigner = ctx["oidc"]
    params = sso_start(api, "entra")
    signer.nonce = params["nonce"]
    signer.claims = claims
    back = api.get(
        "/api/v1/auth/sso/entra/callback",
        params={"code": "good-code", "state": params["state"]},
        follow_redirects=False,
    )
    assert error in fragment(back)["sso_error"]


def test_oidc_refuses_unsigned_or_foreign_tokens(idp_api: tuple[TestClient, Any]) -> None:
    _, ctx = idp_api
    signer: OidcSigner = ctx["oidc"]
    module: OidcIdentityProvider = ctx["orchestrator"].modules["entra"]
    discovery = {"issuer": ISSUER, "jwks_uri": "https://login.example.com/keys"}
    signer.nonce = "n"
    unsigned = jwt.encode(
        {"iss": ISSUER, "aud": CLIENT_ID, "nonce": "n", "sub": "x"}, key=None, algorithm="none"
    )
    import asyncio

    with pytest.raises(ModuleError, match="refused algorithm"):
        asyncio.run(module._verify(discovery, unsigned, "n"))
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time())
    forged = jwt.encode(
        {"iss": ISSUER, "aud": CLIENT_ID, "nonce": "n", "sub": "x", "iat": now, "exp": now + 60},
        other,
        algorithm="RS256",
        headers={"kid": "k1"},
    )
    with pytest.raises(ModuleError, match="not valid"):
        asyncio.run(module._verify(discovery, forged, "n"))


def test_cli_single_sign_on_hands_a_code_to_paste(idp_api: tuple[TestClient, Any]) -> None:
    api, ctx = idp_api
    params = sso_start(api, "entra", return_to="cli")
    ctx["oidc"].nonce = params["nonce"]
    back = api.get(
        "/api/v1/auth/sso/entra/callback",
        params={"code": "good-code", "state": params["state"]},
        follow_redirects=False,
    )
    assert "cli_code" in fragment(back)


# -- SAML -------------------------------------------------------------------------------------


class SamlSigner:
    """A fake SAML identity provider with its own signing certificate."""

    def __init__(self, tmp_path: Path) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.cert_path = tmp_path / "idp.pem"
        self.cert_pem = self._cert(self.key)
        self.cert_path.write_text(self.cert_pem)

    @staticmethod
    def _cert(key: rsa.RSAPrivateKey) -> str:
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idp.example.com")])
        now = dt.datetime.now(dt.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=30))
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM).decode()

    def response(
        self,
        request_id: str,
        *,
        audience: str = SP_ENTITY,
        recipient: str = f"{BASE}/api/v1/auth/sso/saml/callback",
        issuer: str = IDP_ENTITY,
        name_id: str = "Sam@Example.com",
        minutes: int = 5,
        key: rsa.RSAPrivateKey | None = None,
        tamper: bool = False,
        wrap: bool = False,
    ) -> str:
        now = dt.datetime.now(dt.UTC)
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        until = (now + dt.timedelta(minutes=minutes)).strftime(fmt)
        before = (now - dt.timedelta(minutes=1)).strftime(fmt)
        assertion = f"""<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
 ID="_assertion1" Version="2.0" IssueInstant="{now.strftime(fmt)}">
<saml:Issuer>{issuer}</saml:Issuer>
<saml:Subject><saml:NameID>{name_id}</saml:NameID>
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
<saml:SubjectConfirmationData InResponseTo="{request_id}" Recipient="{recipient}"
 NotOnOrAfter="{until}"/></saml:SubjectConfirmation></saml:Subject>
<saml:Conditions NotBefore="{before}" NotOnOrAfter="{until}">
<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>
</saml:Conditions>
<saml:AttributeStatement>
<saml:Attribute Name="http://schemas.microsoft.com/identity/claims/displayname">
<saml:AttributeValue>Sam Saml</saml:AttributeValue></saml:Attribute>
<saml:Attribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/groups">
<saml:AttributeValue>auditors</saml:AttributeValue></saml:Attribute>
</saml:AttributeStatement></saml:Assertion>"""
        signer = XMLSigner(c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")
        signing_key = key or self.key
        signed = signer.sign(
            etree.fromstring(assertion),
            key=signing_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            cert=self.cert_pem if key is None else self._cert(signing_key),
            reference_uri="_assertion1",
        )
        if tamper:
            signed.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}NameID").text = "root"
        response = etree.fromstring(
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            f'ID="_r1" Version="2.0" InResponseTo="{request_id}">'
            "<samlp:Status><samlp:StatusCode "
            'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
            "</samlp:Response>"
        )
        if wrap:
            # Signature wrapping: an unsigned evil assertion placed before the signed one.
            evil = etree.fromstring(assertion.replace(name_id, "root").replace("_assertion1", "_x"))
            response.append(evil)
        response.append(signed)
        return base64.b64encode(etree.tostring(response)).decode()


def saml_post(api: TestClient, state: str, saml_response: str) -> httpx.Response:
    return api.post(
        "/api/v1/auth/sso/saml/callback",
        data={"SAMLResponse": saml_response, "RelayState": state},
        follow_redirects=False,
    )


def request_id_of(params: dict[str, str]) -> str:
    import zlib

    xml = zlib.decompress(base64.b64decode(params["SAMLRequest"]), -15)
    request_id: str = etree.fromstring(xml).get("ID")
    return request_id


def test_saml_single_sign_on(idp_api: tuple[TestClient, Any]) -> None:
    api, ctx = idp_api
    saml: SamlSigner = ctx["saml"]
    params = sso_start(api, "saml")
    request_id = request_id_of(params)
    back = saml_post(api, params["RelayState"], saml.response(request_id))
    session = api.post("/api/v1/auth/sso/exchange", json={"code": fragment(back)["sso"]}).json()
    me = api.get("/api/v1/me", headers=bearer(session["token"])).json()
    assert me["actor"]["id"] == "sam@example.com" and me["actor"]["roles"] == ["auditor"]
    assert me["actor"]["display_name"] == "Sam Saml"
    metadata = api.get("/api/v1/auth/sso/saml/metadata")
    assert SP_ENTITY in metadata.text and "/api/v1/auth/sso/saml/callback" in metadata.text


@pytest.mark.parametrize(
    ("change", "error"),
    [
        ({"tamper": True}, "signature"),
        ({"key": "other"}, "signature"),
        ({"audience": "https://other.example.com"}, "another service"),
        ({"recipient": "https://evil.example.com/acs"}, "not for this sign-in"),
        ({"issuer": "https://evil.example.com"}, "not the configured provider"),
        ({"minutes": -10}, "expired"),
        ({"request_id": "_someone_elses"}, "not for this sign-in"),
    ],
)
def test_saml_refuses_bad_responses(
    idp_api: tuple[TestClient, Any], change: dict[str, Any], error: str
) -> None:
    api, ctx = idp_api
    saml: SamlSigner = ctx["saml"]
    params = sso_start(api, "saml")
    request_id = change.pop("request_id", request_id_of(params))
    if change.get("key") == "other":
        change["key"] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    back = saml_post(api, params["RelayState"], saml.response(request_id, **change))
    assert error in fragment(back)["sso_error"]


def test_saml_signature_wrapping_reads_only_the_signed_assertion(
    idp_api: tuple[TestClient, Any],
) -> None:
    api, ctx = idp_api
    params = sso_start(api, "saml")
    back = saml_post(
        api, params["RelayState"], ctx["saml"].response(request_id_of(params), wrap=True)
    )
    session = api.post("/api/v1/auth/sso/exchange", json={"code": fragment(back)["sso"]}).json()
    assert session["actor"]["id"] == "sam@example.com"


def test_sso_errors_and_audit(idp_api: tuple[TestClient, Any]) -> None:
    api, _ = idp_api
    unknown = api.get("/api/v1/auth/sso/nope/start", follow_redirects=False)
    assert unknown.status_code == 404
    password_only = api.get("/api/v1/auth/sso/ad/start", follow_redirects=False)
    assert password_only.status_code == 404
    forged = api.get(
        "/api/v1/auth/sso/entra/callback", params={"code": "x", "state": "made-up"},
        follow_redirects=False,
    )  # fmt: skip
    assert "expired" in fragment(forged)["sso_error"]
    events = api.get(
        "/api/v1/audit", params={"action": "auth.login"}, headers=bearer(ADMIN_TOKEN)
    ).json()
    assert events[-1]["outcome"] == "failure" and events[-1]["module"] == "entra"
