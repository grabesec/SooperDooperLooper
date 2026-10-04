"""Forwards audit events to Splunk through the HTTP Event Collector (HEC).

Events are sent in batches to ``<url>/services/collector/event``; each one
is the whole audit event as JSON, with the event's own time, so Splunk
searches like ``sourcetype="sdl:audit" action="rollover.target" outcome=failure``
work without extraction rules. The HEC token is read from an environment
variable or a file, never from sdl.yaml.
"""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path
from typing import Any

import httpx
from pydantic import Field, SecretStr, model_validator

from sdl.core.forwarding import tls_context
from sdl.core.models import AuditEvent
from sdl.core.module import ForwarderConfig, ForwarderModule, ModuleError


class SplunkHecConfig(ForwarderConfig):
    url: str = Field(description="HEC base URL, e.g. https://splunk.example.com:8088")
    token_env: str = Field(default="SPLUNK_HEC_TOKEN", description="Env var holding the token.")
    token_file: Path | None = Field(default=None, description="File holding the token instead.")
    index: str | None = Field(default=None, description="Index; defaults to the token's.")
    source: str = "sdl"
    sourcetype: str = "sdl:audit"
    host: str | None = Field(default=None, description="Splunk host field; this server's name.")
    ca_cert: Path | None = None
    tls_verify: bool = True
    timeout: float = Field(default=15, gt=0)
    allow_insecure: bool = Field(
        default=False, description="Allow sending the HEC token over plain http://."
    )

    @model_validator(mode="after")
    def _check(self) -> SplunkHecConfig:
        if self.url.lower().startswith("http://") and not self.allow_insecure:
            raise ValueError(
                "url is http:// and would send the HEC token in clear text; "
                "use https:// or set allow_insecure: true"
            )
        return self


class SplunkHecForwarderModule(ForwarderModule):
    Config = SplunkHecConfig
    description = "Forwards audit events to Splunk's HTTP Event Collector."
    config: SplunkHecConfig

    def __init__(self, config: Any, context: Any) -> None:
        super().__init__(config, context)
        self.endpoint = self.config.url.rstrip("/") + "/services/collector/event"
        self.host = self.config.host or socket.gethostname()
        self._client: httpx.AsyncClient | None = None
        self._transport: httpx.AsyncBaseTransport | None = None  # tests inject a mock

    def _token(self) -> SecretStr:
        if self.config.token_file is not None:
            try:
                return SecretStr(self.config.token_file.read_text(encoding="utf-8").strip())
            except OSError as exc:
                raise ModuleError(f"cannot read {self.config.token_file}: {exc}") from exc
        token = os.environ.get(self.config.token_env)
        if not token:
            raise ModuleError(f"environment variable {self.config.token_env} is not set")
        return SecretStr(token)

    async def start(self) -> None:
        c = self.config
        self._client = httpx.AsyncClient(
            verify=tls_context(c.ca_cert, c.tls_verify, None, None),
            timeout=c.timeout,
            transport=self._transport,
            headers={"Authorization": f"Splunk {self._token().get_secret_value()}"},
        )

    async def stop(self) -> None:
        if self._client is not None:
            await self._client.aclose()

    async def health(self) -> dict[str, Any]:
        return {"ok": True, "destination": self.endpoint}

    def entry(self, event: AuditEvent) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "time": round(event.ts.timestamp(), 6),
            "host": self.host,
            "source": self.config.source,
            "sourcetype": self.config.sourcetype,
            "event": event.model_dump(mode="json"),
        }
        if self.config.index:
            entry["index"] = self.config.index
        return entry

    async def send(self, events: list[AuditEvent]) -> None:
        if self._client is None:
            raise ModuleError("not started")
        body = "\n".join(json.dumps(self.entry(e), separators=(",", ":")) for e in events)
        try:
            response = await self._client.post(self.endpoint, content=body.encode())
        except httpx.HTTPError as exc:
            raise ModuleError(f"cannot reach {self.endpoint}: {exc}") from exc
        if response.status_code != 200:
            try:
                detail = response.json().get("text", response.text)
            except ValueError:
                detail = response.text
            raise ModuleError(f"Splunk HEC answered {response.status_code}: {detail}")
