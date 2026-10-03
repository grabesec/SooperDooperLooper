"""HashiCorp Vault connector (KV version 2 secrets engine).

Authenticates with a token (read from an environment variable or a file) or
with AppRole, which is what a production deployment should use.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

import httpx
from pydantic import Field, SecretStr, model_validator

from sdl.core.models import SecretRecord
from sdl.core.module import ModuleConfig, ModuleError, SecretsModule


class VaultConfig(ModuleConfig):
    url: str = Field(description="Vault address, e.g. https://vault.example.com:8200")
    mount: str = Field(default="secret", description="Mount point of the KV v2 engine.")
    path_prefix: str = Field(default="sdl", description="Prepended to every secret path.")
    namespace: str | None = Field(default=None, description="Vault Enterprise namespace.")
    value_key: str = Field(default="password", description="Key that holds the credential.")
    auth_method: Literal["token", "approle"] = "token"
    token_env: str = Field(default="VAULT_TOKEN", description="Env var holding the token.")
    token_file: Path | None = Field(default=None, description="File holding the token.")
    approle_mount: str = "approle"
    role_id: str | None = None
    secret_id_env: str = Field(
        default="VAULT_SECRET_ID", description="Env var holding the secret id."
    )
    ca_cert: Path | None = Field(default=None, description="CA bundle to verify Vault's TLS cert.")
    tls_verify: bool = True
    timeout: float = 15.0

    @model_validator(mode="after")
    def _check(self) -> VaultConfig:
        if self.auth_method == "approle" and not self.role_id:
            raise ValueError("role_id is required for approle authentication")
        return self


class VaultKV2SecretsModule(SecretsModule):
    Config = VaultConfig
    description = "Stores credentials in a HashiCorp Vault KV v2 engine."
    config: VaultConfig

    def __init__(self, config: Any, context: Any) -> None:
        super().__init__(config, context)
        self._client: httpx.AsyncClient | None = None
        self._token: SecretStr | None = None

    async def start(self) -> None:
        verify: bool | str = (
            str(self.config.ca_cert) if self.config.ca_cert else self.config.tls_verify
        )
        headers = {"X-Vault-Namespace": self.config.namespace} if self.config.namespace else {}
        self._client = httpx.AsyncClient(
            base_url=self.config.url.rstrip("/"),
            verify=verify,
            timeout=self.config.timeout,
            headers=headers,
        )

    async def stop(self) -> None:
        if self._client is not None:
            await self._client.aclose()

    async def health(self) -> dict[str, Any]:
        try:
            response = await self._http().get("/v1/sys/health")
            return {"ok": response.status_code == 200, "status_code": response.status_code}
        except httpx.HTTPError as exc:
            return {"ok": False, "error": str(exc)}

    # -- SecretsModule -----------------------------------------------------

    async def read(self, path: str) -> SecretRecord | None:
        response = await self._request("GET", f"data/{self._path(path)}")
        if response.status_code == 404:
            return None
        body = response.json()["data"]
        data = dict(body.get("data") or {})
        if self.config.value_key not in data:
            raise ModuleError(f"vault secret {path!r} has no {self.config.value_key!r} key")
        value = data.pop(self.config.value_key)
        version = body.get("metadata", {}).get("version")
        return SecretRecord(
            value=SecretStr(value), attributes=data, version=str(version) if version else None
        )

    async def write(self, path: str, record: SecretRecord) -> str | None:
        data = {**record.attributes, self.config.value_key: record.value.get_secret_value()}
        response = await self._request("POST", f"data/{self._path(path)}", json={"data": data})
        version = (response.json().get("data") or {}).get("version")
        return str(version) if version is not None else None

    async def delete(self, path: str) -> None:
        await self._request("DELETE", f"metadata/{self._path(path)}")

    # -- helpers -----------------------------------------------------------

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            raise ModuleError("vault module has not been started")
        return self._client

    def _path(self, path: str) -> str:
        parts = [self.config.path_prefix.strip("/"), path.strip("/")]
        return "/".join(p for p in parts if p)

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        url = f"/v1/{self.config.mount.strip('/')}/{path}"
        for attempt in (1, 2):
            token = await self._get_token()
            try:
                response = await self._http().request(
                    method, url, headers={"X-Vault-Token": token.get_secret_value()}, **kwargs
                )
            except httpx.HTTPError as exc:
                raise ModuleError(f"vault request failed: {exc}") from exc
            if (
                response.status_code == 403
                and attempt == 1
                and self.config.auth_method == "approle"
            ):
                self._token = None  # token may have expired; log in again once
                continue
            if response.status_code == 404 and method == "GET":
                return response
            if response.status_code >= 400:
                raise ModuleError(f"vault {method} {path}: {_errors(response)}")
            return response
        raise ModuleError("vault rejected the AppRole token")  # pragma: no cover

    async def _get_token(self) -> SecretStr:
        if self._token is not None:
            return self._token
        if self.config.auth_method == "approle":
            self._token = await self._approle_login()
        elif self.config.token_file is not None:
            self._token = SecretStr(self.config.token_file.read_text(encoding="utf-8").strip())
        else:
            token = os.environ.get(self.config.token_env)
            if not token:
                raise ModuleError(f"environment variable {self.config.token_env} is not set")
            self._token = SecretStr(token)
        return self._token

    async def _approle_login(self) -> SecretStr:
        secret_id = os.environ.get(self.config.secret_id_env)
        if not secret_id:
            raise ModuleError(f"environment variable {self.config.secret_id_env} is not set")
        try:
            response = await self._http().post(
                f"/v1/auth/{self.config.approle_mount}/login",
                json={"role_id": self.config.role_id, "secret_id": secret_id},
            )
        except httpx.HTTPError as exc:
            raise ModuleError(f"vault login failed: {exc}") from exc
        if response.status_code >= 400:
            raise ModuleError(f"vault AppRole login: {_errors(response)}")
        return SecretStr(response.json()["auth"]["client_token"])


def _errors(response: httpx.Response) -> str:
    try:
        errors = response.json().get("errors") or []
    except ValueError:
        errors = []
    detail = "; ".join(str(e) for e in errors) if errors else response.reason_phrase
    return f"HTTP {response.status_code}: {detail}"
