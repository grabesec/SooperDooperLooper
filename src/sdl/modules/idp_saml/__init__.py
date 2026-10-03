"""SAML 2.0 single sign-on: Entra ID, AD FS, Okta, Shibboleth, Keycloak...

SDL is the service provider. The browser is sent to the identity provider
with an AuthnRequest (HTTP-Redirect binding) and comes back with a signed
SAML response posted to SDL's callback (HTTP-POST binding, the assertion
consumer service). SDL checks the XML signature against the identity
provider's certificate and only reads the signed part, then checks the
issuer, audience, recipient, validity window and that the response answers
the request SDL sent (so it cannot be replayed). Encrypted assertions are not
supported: rely on HTTPS between the browser and SDL.

Give the identity provider SDL's metadata:
``GET /api/v1/auth/sso/<instance id>/metadata``.

Needs signxml: ``pip install 'sooperdooperlooper[saml]'``.
"""

from __future__ import annotations

import base64
import secrets
import zlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode
from xml.sax.saxutils import escape, quoteattr

from pydantic import Field

from sdl.core.models import ExternalIdentity
from sdl.core.module import IdentityProviderModule, IdpConfig, ModuleError, SsoStart

if TYPE_CHECKING:
    from lxml.etree import _Element

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
MAX_RESPONSE = 512 * 1024


class SamlConfig(IdpConfig):
    sp_entity_id: str = Field(
        description="SDL's entity id as registered at the identity provider, e.g. "
        "https://sdl.example.com/saml."
    )
    idp_entity_id: str = Field(description="The identity provider's entity id (Issuer).")
    idp_sso_url: str = Field(description="The identity provider's single sign-on URL.")
    idp_certificates: list[Path] = Field(
        min_length=1,
        description="PEM files with the identity provider's signing certificate(s); list two "
        "while it rolls its certificate over.",
    )
    username_attribute: str | None = Field(
        default=None, description="Attribute used as the SDL user name; the NameID when unset."
    )
    groups_attribute: str = Field(
        default="http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
        description="Attribute listing the user's groups (default: Entra ID / AD FS groups).",
    )
    display_name_attribute: str = "http://schemas.microsoft.com/identity/claims/displayname"
    email_attribute: str = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
    clock_skew: float = Field(default=120, ge=0, description="Seconds of clock difference allowed.")


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class SamlIdentityProvider(IdentityProviderModule):
    Config = SamlConfig
    description = "Single sign-on with SAML 2.0 (Entra ID, AD FS, Okta, Shibboleth...)."
    config: SamlConfig
    login = "redirect"

    def __init__(self, config: Any, context: Any) -> None:
        super().__init__(config, context)
        self._certs: list[str] = []

    async def start(self) -> None:
        try:
            import signxml  # noqa: F401
        except ImportError as exc:  # pragma: no cover - depends on the installation
            raise ModuleError("signxml is needed: pip install 'sooperdooperlooper[saml]'") from exc
        self._load_certs()

    def _load_certs(self) -> list[str]:
        if not self._certs:
            try:
                self._certs = [p.read_text(encoding="ascii") for p in self.config.idp_certificates]
            except OSError as exc:
                raise ModuleError(
                    f"cannot read the identity provider's certificate: {exc}"
                ) from exc
        return self._certs

    def metadata(self, callback_url: str) -> str:
        entity = quoteattr(self.config.sp_entity_id)
        acs = quoteattr(callback_url)
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
            f"entityID={entity}>"
            '<md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" '
            'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
            "<md:AssertionConsumerService "
            'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
            f'Location={acs} index="0" isDefault="true"/>'
            "</md:SPSSODescriptor></md:EntityDescriptor>\n"
        )

    async def begin(self, callback_url: str, state: str) -> SsoStart:
        request_id = "_" + secrets.token_hex(20)
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        request = (
            f'<samlp:AuthnRequest xmlns:samlp="{NS["samlp"]}" xmlns:saml="{NS["saml"]}" '
            f'ID="{request_id}" Version="2.0" IssueInstant="{now}" '
            f"Destination={quoteattr(self.config.idp_sso_url)} "
            f"AssertionConsumerServiceURL={quoteattr(callback_url)} "
            'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
            f"<saml:Issuer>{escape(self.config.sp_entity_id)}</saml:Issuer>"
            "</samlp:AuthnRequest>"
        )
        deflated = zlib.compress(request.encode())[2:-4]  # raw DEFLATE, as the binding wants
        query = urlencode({"SAMLRequest": base64.b64encode(deflated).decode(), "RelayState": state})
        separator = "&" if "?" in self.config.idp_sso_url else "?"
        return SsoStart(
            url=f"{self.config.idp_sso_url}{separator}{query}", state={"request_id": request_id}
        )

    async def complete(
        self, params: dict[str, str], state: dict[str, Any], callback_url: str
    ) -> ExternalIdentity:
        encoded = params.get("SAMLResponse")
        if not encoded:
            raise ModuleError("the identity provider sent no SAML response")
        if len(encoded) > MAX_RESPONSE:
            raise ModuleError("the SAML response is too large")
        try:
            xml = base64.b64decode(encoded, validate=False)
        except ValueError as exc:
            raise ModuleError("the SAML response is not base64") from exc
        assertion = self._verified_assertion(xml, state["request_id"], callback_url)
        return self._identity(assertion)

    def _verified_assertion(self, xml: bytes, request_id: str, callback_url: str) -> _Element:
        from lxml import etree
        from signxml.exceptions import InvalidInput, InvalidSignature
        from signxml.verifier import SignatureConfiguration, XMLVerifier

        parser = etree.XMLParser(
            resolve_entities=False, no_network=True, huge_tree=False, remove_comments=True
        )
        try:
            root = etree.fromstring(xml, parser=parser)
        except etree.XMLSyntaxError as exc:
            raise ModuleError(f"the SAML response is not valid XML: {exc}") from exc
        if root.tag != f"{{{NS['samlp']}}}Response":
            raise ModuleError("this is not a SAML response")
        status = root.find("samlp:Status/samlp:StatusCode", NS)
        if status is None or status.get("Value") != SUCCESS:
            raise ModuleError(
                "the identity provider reports that sign-in failed"
                + (f" ({status.get('Value')})" if status is not None else "")
            )
        if root.find("saml:EncryptedAssertion", NS) is not None:
            raise ModuleError("encrypted assertions are not supported; turn encryption off")

        # Only what the signature covers is trusted: everything below reads the
        # element signxml hands back, never the document as received.
        signed: _Element | None = None
        errors = []
        for cert in self._load_certs():
            try:
                result = XMLVerifier().verify(
                    xml,
                    x509_cert=cert,
                    parser=parser,
                    expect_config=SignatureConfiguration(ignore_ambiguous_key_info=True),
                )
            except (InvalidSignature, InvalidInput) as exc:
                errors.append(str(exc))
                continue
            results = result if isinstance(result, list) else [result]
            signed = results[0].signed_xml
            break
        if signed is None:
            raise ModuleError(f"the SAML response's signature is not valid: {'; '.join(errors)}")

        if signed.tag == f"{{{NS['saml']}}}Assertion":
            assertion = signed
        elif signed.tag == f"{{{NS['samlp']}}}Response":
            found = signed.findall("saml:Assertion", NS)
            if len(found) != 1:
                raise ModuleError("the signed response must hold exactly one assertion")
            assertion = found[0]
            if signed.get("InResponseTo") not in (None, request_id):
                raise ModuleError("the SAML response answers another sign-in")
            if signed.get("Destination") not in (None, callback_url):
                raise ModuleError("the SAML response was sent to another address")
        else:
            raise ModuleError("the signature covers neither the response nor the assertion")
        self._check(assertion, request_id, callback_url)
        return assertion

    def _check(self, assertion: _Element, request_id: str, callback_url: str) -> None:
        now = datetime.now(UTC)
        skew = timedelta(seconds=self.config.clock_skew)
        issuer = assertion.findtext("saml:Issuer", namespaces=NS)
        if (issuer or "").strip() != self.config.idp_entity_id:
            raise ModuleError(f"the assertion comes from {issuer!r}, not the configured provider")

        conditions = assertion.find("saml:Conditions", NS)
        if conditions is None:
            raise ModuleError("the assertion has no validity conditions")
        not_before = _parse_time(conditions.get("NotBefore"))
        not_after = _parse_time(conditions.get("NotOnOrAfter"))
        if not_before and now + skew < not_before:
            raise ModuleError("the assertion is not valid yet; check the clocks")
        if not_after and now - skew >= not_after:
            raise ModuleError("the assertion has expired")
        audiences = [
            (a.text or "").strip()
            for a in conditions.findall("saml:AudienceRestriction/saml:Audience", NS)
        ]
        if self.config.sp_entity_id not in audiences:
            raise ModuleError("the assertion is meant for another service")

        confirmed = False
        for confirmation in assertion.findall("saml:Subject/saml:SubjectConfirmation", NS):
            if confirmation.get("Method") != BEARER:
                continue
            data = confirmation.find("saml:SubjectConfirmationData", NS)
            if data is None:
                continue
            until = _parse_time(data.get("NotOnOrAfter"))
            if (
                data.get("InResponseTo") == request_id
                and data.get("Recipient") == callback_url
                and until is not None
                and now - skew < until
            ):
                confirmed = True
                break
        if not confirmed:
            raise ModuleError(
                "the assertion is not for this sign-in (recipient, request or time do not match)"
            )

    def _attributes(self, assertion: _Element) -> dict[str, list[str]]:
        values: dict[str, list[str]] = {}
        for attribute in assertion.findall("saml:AttributeStatement/saml:Attribute", NS):
            name = attribute.get("Name") or ""
            values[name] = [
                (v.text or "").strip() for v in attribute.findall("saml:AttributeValue", NS)
            ]
        return values

    def _identity(self, assertion: _Element) -> ExternalIdentity:
        attributes = self._attributes(assertion)
        if self.config.username_attribute:
            username = next(iter(attributes.get(self.config.username_attribute, [])), "")
        else:
            username = (assertion.findtext("saml:Subject/saml:NameID", namespaces=NS) or "").strip()
        if not username:
            raise ModuleError("the assertion does not name the user")
        display = next(iter(attributes.get(self.config.display_name_attribute, [])), None)
        email = next(iter(attributes.get(self.config.email_attribute, [])), None)
        return ExternalIdentity(
            username=username,
            display_name=display or None,
            email=email or None,
            groups=[g for g in attributes.get(self.config.groups_attribute, []) if g],
        )
