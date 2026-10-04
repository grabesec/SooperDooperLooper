"""Forwards audit events to a syslog server as RFC 5424 messages.

Over UDP (RFC 5426), TCP (RFC 6587, octet-counting or newline framing) or TLS
(RFC 5425). Each message carries the event's identifying fields as structured
data (``[sdl@32473 event_id="..." outcome="..." actor="..." target="..."]``),
the action as MSGID, and the whole event as JSON in the message body, so a
log concentrator can index it and still check it against the hash chain.
"""

from __future__ import annotations

import os
import re
import socket
from pathlib import Path
from typing import Any, Literal

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
from sdl.core.module import ForwarderConfig, ForwarderModule

FACILITIES = {
    "kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5, "lpr": 6, "news": 7,
    "uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11, "local0": 16, "local1": 17, "local2": 18,
    "local3": 19, "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}  # fmt: skip
DEFAULT_PORTS = {"udp": 514, "tcp": 514, "tls": 6514}


class SyslogConfig(ForwarderConfig):
    host: str = Field(description="Syslog server or log concentrator.")
    port: int | None = Field(default=None, ge=1, le=65535, description="514, or 6514 for TLS.")
    protocol: Literal["udp", "tcp", "tls"] = "tcp"
    framing: Literal["octet-counting", "newline"] = Field(
        default="octet-counting", description="TCP/TLS message framing (RFC 6587)."
    )
    facility: str = Field(default="authpriv", description="Syslog facility name.")
    app_name: str = Field(default="sdl", max_length=48)
    hostname: str | None = Field(default=None, description="Defaults to this server's name.")
    sd_id: str = Field(
        default="sdl@32473",
        pattern=r"^[!#-<>-\\^-~]{1,32}$",
        description="Structured-data id; replace 32473 with your own IANA enterprise number.",
    )
    body: Literal["json", "text"] = Field(
        default="json", description="Message body: the whole event as JSON, or a one-line summary."
    )
    max_udp_size: int = Field(default=8192, ge=480, le=65000)
    ca_cert: Path | None = Field(default=None, description="CA bundle to verify the server.")
    tls_verify: bool = True
    client_cert: Path | None = Field(default=None, description="Client certificate (mutual TLS).")
    client_key: Path | None = None
    timeout: float = Field(default=10, gt=0)

    @model_validator(mode="after")
    def _check(self) -> SyslogConfig:
        if self.facility not in FACILITIES:
            raise ValueError(f"facility must be one of {', '.join(FACILITIES)}")
        if self.protocol != "tls" and (self.ca_cert or self.client_cert):
            raise ValueError("ca_cert and client_cert only apply to protocol: tls")
        return self


def _printable(text: str, limit: int) -> str:
    """RFC 5424 header fields are printable US-ASCII without spaces."""
    cleaned = "".join(c if 33 <= ord(c) <= 126 else "_" for c in text)
    return cleaned[:limit] or "-"


_CONTROL = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029]")


def _clean(text: str) -> str:
    """Drop control characters and line separators so one event stays one line."""
    return _CONTROL.sub(" ", text)


def _param(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


class SyslogForwarderModule(ForwarderModule):
    Config = SyslogConfig
    description = "Forwards audit events to syslog (RFC 5424 over UDP, TCP or TLS)."
    config: SyslogConfig

    def __init__(self, config: Any, context: Any) -> None:
        super().__init__(config, context)
        c = self.config
        self.port = c.port or DEFAULT_PORTS[c.protocol]
        self.hostname = _printable(c.hostname or socket.gethostname(), 255)
        self._stream: StreamConnection | None = None
        self._datagrams: DatagramSender | None = None
        if c.protocol == "udp":
            self._datagrams = DatagramSender(c.host, self.port)
        else:
            context_ = (
                tls_context(c.ca_cert, c.tls_verify, c.client_cert, c.client_key)
                if c.protocol == "tls"
                else None
            )
            self._stream = StreamConnection(c.host, self.port, context_, c.timeout)

    async def stop(self) -> None:
        if self._stream is not None:
            await self._stream.close()
        if self._datagrams is not None:
            await self._datagrams.close()

    async def health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "destination": f"{self.config.protocol}://{self.config.host}:{self.port}",
        }

    def format(self, event: AuditEvent) -> bytes:
        c = self.config
        pri = FACILITIES[c.facility] * 8 + SEVERITY[event.outcome]
        ts = event.ts.isoformat(timespec="microseconds").replace("+00:00", "Z")
        params = " ".join(f'{k}="{_param(v)}"' for k, v in fields(event).items())
        header = (
            f"<{pri}>1 {ts} {self.hostname} {_printable(c.app_name, 48)} {os.getpid()} "
            f"{_printable(event.action, 32)} [{c.sd_id} {params}] "
        )
        body = event.model_dump_json() if c.body == "json" else _clean(summary(event))
        message = (header + body).encode()
        if c.protocol == "udp" and len(message) > c.max_udp_size:
            # Too big for one datagram: send the summary rather than cut the JSON in half.
            message = (header + _clean(summary(event))).encode()[: c.max_udp_size]
        return message

    def frame(self, message: bytes) -> bytes:
        if self.config.framing == "newline":
            return message.replace(b"\n", b" ") + b"\n"
        return str(len(message)).encode() + b" " + message

    async def send(self, events: list[AuditEvent]) -> None:
        messages = [self.format(e) for e in events]
        if self._datagrams is not None:
            await self._datagrams.send(messages)
        elif self._stream is not None:
            await self._stream.write(b"".join(self.frame(m) for m in messages))
