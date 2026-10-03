"""Delivery of audit events to forwarder modules (syslog, Graylog, Splunk, ...).

Each forwarder gets its own in-memory queue and background task. Recording an
event only appends it to the queues, so a slow or unreachable destination
never delays or breaks the local audit log, which stays the record of truth.
When a destination is down, events wait (up to the forwarder's
``queue_size``, oldest dropped first) and are retried with back-off. A
forwarder going down and coming back is itself recorded in the audit log.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
import ssl
from collections import deque
from collections.abc import Awaitable, Callable
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel

from sdl.core.models import AuditEvent, Outcome, action_matches, utcnow
from sdl.core.module import ForwarderModule, ModuleError

log = logging.getLogger("sdl.forwarding")

StatusCallback = Callable[[ForwarderModule, bool, str], Awaitable[None]]


class ForwarderStatus(BaseModel):
    id: str
    ok: bool
    queued: int
    sent: int
    dropped: int
    failures: int
    last_error: str | None = None
    last_error_at: datetime | None = None
    last_sent_at: datetime | None = None


class _Channel:
    def __init__(self, module: ForwarderModule, on_status: StatusCallback) -> None:
        self.module = module
        self.config = module.config
        self.on_status = on_status
        self.queue: deque[tuple[int, AuditEvent]] = deque()
        self.seq = 0
        self.wake = asyncio.Event()
        self.idle = asyncio.Event()
        self.idle.set()
        self.task: asyncio.Task[None] | None = None
        self.ok = True
        self.sent = 0
        self.dropped = 0
        self.failures = 0
        self.last_error: str | None = None
        self.last_error_at: datetime | None = None
        self.last_sent_at: datetime | None = None

    def wants(self, event: AuditEvent) -> bool:
        if self.config.actions and not any(
            action_matches(event.action, p) for p in self.config.actions
        ):
            return False
        return not any(action_matches(event.action, p) for p in self.config.exclude_actions)

    def publish(self, event: AuditEvent) -> None:
        if not self.wants(event):
            return
        if len(self.queue) >= self.config.queue_size:
            self.queue.popleft()
            self.dropped += 1
            if self.dropped == 1 or self.dropped % 1000 == 0:
                log.warning(
                    "forwarder %s: queue full, %d event(s) dropped so far (still in the local log)",
                    self.module.instance_id,
                    self.dropped,
                )
        self.seq += 1
        self.queue.append((self.seq, event))
        self.idle.clear()
        self.wake.set()

    async def run(self) -> None:
        delay = min(1.0, self.config.retry_max_delay)
        while True:
            if not self.queue:
                self.idle.set()
                self.wake.clear()
                await self.wake.wait()
                continue
            batch = list(itertools.islice(self.queue, self.config.batch_size))
            last_seq = batch[-1][0]
            events = [event for _, event in batch]
            try:
                await self.module.send(events)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.failures += 1
                self.last_error = str(exc) or type(exc).__name__
                self.last_error_at = utcnow()
                log.warning(
                    "forwarder %s: delivery failed, retrying in %.0fs: %s",
                    self.module.instance_id,
                    delay,
                    self.last_error,
                )
                if self.ok:
                    self.ok = False
                    await self.on_status(self.module, False, self.last_error)
                await asyncio.sleep(delay)
                delay = min(delay * 2, self.config.retry_max_delay)
                continue
            # Events dropped while sending may have shifted the queue; drop by sequence.
            while self.queue and self.queue[0][0] <= last_seq:
                self.queue.popleft()
            self.sent += len(events)
            self.last_sent_at = utcnow()
            delay = min(1.0, self.config.retry_max_delay)
            if not self.ok:
                self.ok = True
                await self.on_status(self.module, True, f"delivering again; {self.dropped} dropped")

    def status(self) -> ForwarderStatus:
        return ForwarderStatus(
            id=self.module.instance_id,
            ok=self.ok,
            queued=len(self.queue),
            sent=self.sent,
            dropped=self.dropped,
            failures=self.failures,
            last_error=self.last_error,
            last_error_at=self.last_error_at,
            last_sent_at=self.last_sent_at,
        )


class Forwarding:
    """Queues every recorded audit event for every forwarder module and delivers it."""

    def __init__(self) -> None:
        self._channels: dict[str, _Channel] = {}

    def attach(self, modules: list[ForwarderModule], on_status: StatusCallback) -> None:
        self._channels = {m.instance_id: _Channel(m, on_status) for m in modules}

    def publish(self, event: AuditEvent) -> None:
        """Queue the event; never blocks and never raises."""
        for channel in self._channels.values():
            try:
                channel.publish(event)
            except Exception:
                log.exception("forwarder %s: could not queue an event", channel.module.instance_id)

    def start(self) -> None:
        for instance_id, channel in self._channels.items():
            if channel.task is None:
                channel.task = asyncio.create_task(channel.run(), name=f"forward-{instance_id}")

    async def stop(self) -> None:
        """Give each reachable destination ``flush_timeout`` seconds to take what is queued."""

        async def flush(channel: _Channel) -> None:
            if channel.task is None:
                return
            if channel.ok and channel.queue:
                try:
                    await asyncio.wait_for(channel.idle.wait(), channel.config.flush_timeout)
                except TimeoutError:
                    pass
            if channel.queue:
                log.warning(
                    "forwarder %s: %d event(s) not delivered at shutdown (still in the local log)",
                    channel.module.instance_id,
                    len(channel.queue),
                )
            channel.task.cancel()
            await asyncio.gather(channel.task, return_exceptions=True)
            channel.task = None

        await asyncio.gather(*(flush(c) for c in self._channels.values()))

    def status(self) -> list[ForwarderStatus]:
        return [c.status() for c in self._channels.values()]


# -- helpers for forwarder modules ---------------------------------------------

SEVERITY = {
    Outcome.FAILURE: 3,  # error
    Outcome.DENIED: 4,  # warning
    Outcome.SUCCESS: 5,  # notice
    Outcome.STARTED: 6,  # informational
    Outcome.INFO: 6,
}
"""Syslog severity of each outcome, also used as the GELF level."""


def summary(event: AuditEvent) -> str:
    """One readable line: ``rollover.target success web1 by system:orchestrator for bob: ...``."""
    parts = [event.action, event.outcome.value]
    if event.target:
        parts.append(event.target)
    who = f"by {event.actor.type.value}:{event.actor.id}"
    if event.initiated_by is not None:
        who += f" for {event.initiated_by.id}"
    parts.append(who)
    line = " ".join(parts)
    return f"{line}: {event.message}" if event.message else line


def fields(event: AuditEvent) -> dict[str, str]:
    """The event's identifying fields as flat strings, for formats without nesting."""
    values = {
        "event_id": event.id,
        "action": event.action,
        "outcome": event.outcome.value,
        "actor": event.actor.id,
        "actor_type": event.actor.type.value,
        "initiated_by": event.initiated_by.id if event.initiated_by else None,
        "target": event.target,
        "module": event.module,
        "run_id": event.run_id,
        "hash": event.hash,
        "prev_hash": event.prev_hash,
    }
    return {k: v for k, v in values.items() if v is not None}


def tls_context(
    ca_cert: Path | None, verify: bool, client_cert: Path | None, client_key: Path | None
) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=str(ca_cert) if ca_cert else None)
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if client_cert is not None:
        context.load_cert_chain(str(client_cert), str(client_key) if client_key else None)
    return context


class StreamConnection:
    """A TCP (or TLS) connection that reconnects on the next write after any error."""

    def __init__(
        self, host: str, port: int, ssl_context: ssl.SSLContext | None, timeout: float
    ) -> None:
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self.timeout = timeout
        self._writer: asyncio.StreamWriter | None = None

    async def _connection(self) -> asyncio.StreamWriter:
        if self._writer is not None and not self._writer.is_closing():
            return self._writer
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(
                self.host,
                self.port,
                ssl=self.ssl_context,
                server_hostname=self.host if self.ssl_context else None,
            ),
            self.timeout,
        )
        self._writer = writer
        return writer

    async def write(self, data: bytes) -> None:
        try:
            writer = await self._connection()
            writer.write(data)
            await asyncio.wait_for(writer.drain(), self.timeout)
        except (OSError, TimeoutError, ssl.SSLError) as exc:
            await self.close()
            raise ModuleError(
                f"cannot send to {self.host}:{self.port}: {str(exc) or type(exc).__name__}"
            ) from exc

    async def close(self) -> None:
        writer, self._writer = self._writer, None
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), self.timeout)
            except (OSError, TimeoutError, ssl.SSLError):
                pass


class DatagramSender:
    """Sends UDP datagrams. Delivery is not confirmed: UDP has no acknowledgements."""

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self._transport: asyncio.DatagramTransport | None = None

    async def send(self, datagrams: list[bytes]) -> None:
        try:
            if self._transport is None or self._transport.is_closing():
                loop = asyncio.get_running_loop()
                self._transport, _ = await loop.create_datagram_endpoint(
                    asyncio.DatagramProtocol, remote_addr=(self.host, self.port)
                )
            for datagram in datagrams:
                self._transport.sendto(datagram)
        except OSError as exc:
            await self.close()
            raise ModuleError(f"cannot send to {self.host}:{self.port}: {exc}") from exc

    async def close(self) -> None:
        transport, self._transport = self._transport, None
        if transport is not None:
            transport.close()
