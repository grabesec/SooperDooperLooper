"""Forwards audit events to Graylog (or anything that reads GELF 1.1).

Transports: ``http`` (a GELF HTTP input, which confirms every message),
``tcp`` and ``tls`` (null-byte delimited), and ``udp`` (chunked when large,
optionally gzip-compressed). Every event becomes one GELF message whose
``short_message`` is a readable summary; the event's fields are additional
fields (``_sdl_action``, ``_sdl_target``, ``_sdl_actor``, ...) and
``_sdl_details`` holds its details as JSON.
"""

from __future__ import annotations

import gzip
import json
import os
import socket
from pathlib import Path
from typing import Any, Literal

import httpx
from pydantic import Field, model_validator

from sdl.core.forwarding import (
    SEVERITY,
    DatagramSender,
    StreamConnection,
    fields,
    summary,
    tls_context,
)
from sdl.core.models import AuditEvent
from sdl.core.module import ForwarderConfig, ForwarderModule, ModuleError

CHUNK_MAGIC = b"\x1e\x0f"
MAX_CHUNKS = 128


class GelfConfig(ForwarderConfig):
    transport: Literal["http", "tcp", "tls", "udp"] = "http"
    url: str | None = Field(
        default=None, description="GELF HTTP input, e.g. http://graylog:12201/gelf (http only)."
    )
    host: str | None = Field(default=None, description="Graylog host (tcp, tls, udp).")
    port: int = Field(default=12201, ge=1, le=65535)
    auth_header: str | None = Field(
        default=None, description="Header the HTTP input requires, e.g. Authorization."
    )
    auth_value_env: str | None = Field(
        default=None, description="Env var holding that header's value."
    )
    source: str | None = Field(default=None, description="GELF host field; this server's name.")
    compress: bool = Field(default=False, description="gzip each UDP message.")
    chunk_size: int = Field(default=1420, ge=512, le=65000, description="UDP chunk size.")
    ca_cert: Path | None = None
    tls_verify: bool = True
    client_cert: Path | None = None
    client_key: Path | None = None
    timeout: float = Field(default=10, gt=0)
    allow_insecure: bool = Field(
        default=False, description="Allow sending auth_header over plain http://."
    )

    @model_validator(mode="after")
    def _check(self) -> GelfConfig:
        if self.transport == "http" and not self.url:
            raise ValueError("url is required for transport: http")
        if self.transport != "http" and not self.host:
            raise ValueError(f"host is required for transport: {self.transport}")
        if bool(self.auth_header) != bool(self.auth_value_env):
            raise ValueError("auth_header and auth_value_env go together")
        if (
            self.auth_header
            and self.url
            and self.url.lower().startswith("http://")
            and not self.allow_insecure
        ):
            raise ValueError(
                "url is http:// and would send auth_header in clear text; "
                "use https:// or set allow_insecure: true"
            )
        return self


class GelfForwarderModule(ForwarderModule):
    Config = GelfConfig
    description = "Forwards audit events to Graylog as GELF (HTTP, TCP, TLS or UDP)."
    config: GelfConfig

    def __init__(self, config: Any, context: Any) -> None:
        super().__init__(config, context)
        self.source = self.config.source or socket.gethostname()
        self._http: httpx.AsyncClient | None = None
        self._transport: httpx.AsyncBaseTransport | None = None  # tests inject a mock
        self._stream: StreamConnection | None = None
        self._datagrams: DatagramSender | None = None

    async def start(self) -> None:
        c = self.config
        if c.transport == "http":
            headers = {}
            if c.auth_header and c.auth_value_env:
                value = os.environ.get(c.auth_value_env)
                if not value:
                    raise ModuleError(f"environment variable {c.auth_value_env} is not set")
                headers[c.auth_header] = value
            self._http = httpx.AsyncClient(
                verify=tls_context(c.ca_cert, c.tls_verify, c.client_cert, c.client_key),
                timeout=c.timeout,
                transport=self._transport,
                headers=headers,
            )
        elif c.transport == "udp":
            assert c.host is not None
            self._datagrams = DatagramSender(c.host, c.port)
        else:
            assert c.host is not None
            context = (
                tls_context(c.ca_cert, c.tls_verify, c.client_cert, c.client_key)
                if c.transport == "tls"
                else None
            )
            self._stream = StreamConnection(c.host, c.port, context, c.timeout)

    async def stop(self) -> None:
        if self._http is not None:
            await self._http.aclose()
        if self._stream is not None:
            await self._stream.close()
        if self._datagrams is not None:
            await self._datagrams.close()

    async def health(self) -> dict[str, Any]:
        c = self.config
        where = c.url if c.transport == "http" else f"{c.transport}://{c.host}:{c.port}"
        return {"ok": True, "destination": where}

    def message(self, event: AuditEvent) -> dict[str, Any]:
        gelf: dict[str, Any] = {
            "version": "1.1",
            "host": self.source,
            "short_message": summary(event),
            "timestamp": round(event.ts.timestamp(), 6),
            "level": SEVERITY[event.outcome],
            "_sdl_ts": event.ts.isoformat(),
        }
        if event.message:
            gelf["full_message"] = event.message
        for key, value in fields(event).items():
            gelf[f"_sdl_{key}"] = value
        if event.details:
            gelf["_sdl_details"] = json.dumps(event.details, sort_keys=True, default=str)
        return gelf

    def datagrams(self, payload: bytes) -> list[bytes]:
        if self.config.compress:
            payload = gzip.compress(payload)
        if len(payload) <= self.config.chunk_size:
            return [payload]
        size = self.config.chunk_size - 12
        parts = [payload[i : i + size] for i in range(0, len(payload), size)]
        if len(parts) > MAX_CHUNKS:
            raise ModuleError(f"GELF message too large for UDP ({len(payload)} bytes)")
        message_id = os.urandom(8)
        return [
            CHUNK_MAGIC + message_id + bytes([n, len(parts)]) + part for n, part in enumerate(parts)
        ]

    async def send(self, events: list[AuditEvent]) -> None:
        payloads = [json.dumps(self.message(e), separators=(",", ":")).encode() for e in events]
        if self._http is not None:
            assert self.config.url is not None
            for payload in payloads:
                try:
                    response = await self._http.post(
                        self.config.url,
                        content=payload,
                        headers={"Content-Type": "application/json"},
                    )
                except httpx.HTTPError as exc:
                    raise ModuleError(f"cannot reach {self.config.url}: {exc}") from exc
                if response.status_code >= 300:
                    raise ModuleError(
                        f"{self.config.url} answered {response.status_code}: {response.text[:200]}"
                    )
        elif self._stream is not None:
            await self._stream.write(b"".join(p + b"\0" for p in payloads))
        elif self._datagrams is not None:
            datagrams: list[bytes] = []
            for payload in payloads:
                datagrams.extend(self.datagrams(payload))
            await self._datagrams.send(datagrams)
