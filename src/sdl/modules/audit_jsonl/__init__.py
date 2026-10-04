"""Audit module that appends events to a hash-chained JSON Lines file.

Each event stores the hash of the event before it, so editing or deleting a
line breaks the chain and ``verify()`` reports where.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
from collections import deque
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from pydantic import Field

from sdl.core.models import AuditEvent, AuditFacets, AuditQuery
from sdl.core.module import AuditModule, ModuleConfig

GENESIS = "0" * 64
log = logging.getLogger(__name__)


class JsonlAuditConfig(ModuleConfig):
    path: Path = Field(description="File to append audit events to.")
    fsync: bool = Field(default=True, description="fsync after every event.")
    hmac_key_env: str | None = Field(
        default=None,
        description="Name of an env var holding an HMAC key; when set, hashes are HMAC-SHA256.",
    )


def event_hash(event: AuditEvent, key: bytes | None = None) -> str:
    body = event.model_dump(mode="json", exclude={"hash"})
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    if key:
        return hmac.new(key, canonical, hashlib.sha256).hexdigest()
    return hashlib.sha256(canonical).hexdigest()


class JsonlAuditModule(AuditModule):
    Config = JsonlAuditConfig
    description = "Append-only, hash-chained JSON Lines audit log."
    config: JsonlAuditConfig

    def __init__(self, config: Any, context: Any) -> None:
        super().__init__(config, context)
        self._lock = asyncio.Lock()
        self._last_hash = GENESIS
        self._key: bytes | None = None
        self.start_error: str | None = None
        self._started = False

    def _hash(self, event: AuditEvent) -> str:
        return event_hash(event, self._key)

    async def start(self) -> None:
        env = self.config.hmac_key_env
        if env and os.environ.get(env):
            self._key = os.environ[env].encode()
        else:
            log.warning(
                "audit_jsonl: no HMAC key configured (hmac_key_env); hash chain uses plain "
                "SHA-256 and can be rewritten by anyone with write access to the file"
            )
        path = self.config.path
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            last = None
            with path.open(encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        last = line
            if last:
                try:
                    event = AuditEvent.model_validate_json(last)
                except ValueError:
                    self.start_error = "last audit line is malformed"
                    log.error("audit_jsonl: %s; continuing chain from it anyway", self.start_error)
                    try:
                        self._last_hash = json.loads(last)["hash"]
                    except (ValueError, KeyError, TypeError):
                        pass
                else:
                    if event.hash != self._hash(event):
                        self.start_error = f"last audit line (event {event.id}) hash mismatch"
                        log.error("audit_jsonl: %s", self.start_error)
                    self._last_hash = event.hash or self._last_hash
        else:
            fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)
        self._started = True

    async def write(self, event: AuditEvent) -> AuditEvent:
        async with self._lock:
            event.prev_hash = self._last_hash
            event.hash = self._hash(event)
            line = event.model_dump_json() + "\n"
            await asyncio.to_thread(self._append, line)
            self._last_hash = event.hash
            return event

    def _append(self, line: str) -> None:
        with self.config.path.open("a", encoding="utf-8") as fh:
            size = fh.seek(0, os.SEEK_END)
            try:
                fh.write(line)
                fh.flush()
                if self.config.fsync:
                    os.fsync(fh.fileno())
            except BaseException:
                try:
                    fh.truncate(size)
                except OSError:
                    pass
                raise

    def _iter_lines(self) -> Iterator[tuple[int, AuditEvent | None]]:
        """Yield (line number, event or None if malformed) for every non-blank line."""
        if not self.config.path.exists():
            return
        with self.config.path.open(encoding="utf-8", errors="replace") as fh:
            for number, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                try:
                    yield number, AuditEvent.model_validate_json(line)
                except ValueError:
                    yield number, None

    def _iter(self) -> Iterator[AuditEvent]:
        for number, event in self._iter_lines():
            if event is None:
                log.warning("audit_jsonl: skipping malformed line %d", number)
                continue
            yield event

    def _read_all(self) -> list[tuple[int, AuditEvent | None]]:
        return list(self._iter_lines())

    async def query(self, query: AuditQuery) -> list[AuditEvent]:
        def scan() -> list[AuditEvent]:
            matches: deque[AuditEvent] = deque(maxlen=query.limit)
            for event in self._iter():
                if query.matches(event):
                    matches.append(event)
            return list(reversed(matches)) if query.newest_first else list(matches)

        async with self._lock:
            return await asyncio.to_thread(scan)

    async def facets(self, query: AuditQuery | None = None) -> AuditFacets:
        def scan() -> AuditFacets:
            facets = AuditFacets()
            for event in self._iter():
                if query is None or query.matches(event):
                    facets.add(event)
            return facets

        async with self._lock:
            return await asyncio.to_thread(scan)

    async def verify(self) -> tuple[bool, str]:
        async with self._lock:
            events = await asyncio.to_thread(self._read_all)
            last_hash = self._last_hash
        expected_prev = GENESIS
        for index, event in events:
            if event is None:
                return False, f"line {index} is malformed"
            if event.prev_hash != expected_prev:
                return (
                    False,
                    f"chain broken at line {index} (event {event.id}): missing or reordered events",
                )
            if event.hash != self._hash(event):
                return False, f"line {index} (event {event.id}) was modified"
            expected_prev = event.hash
        if self._started and expected_prev != last_hash:
            return (
                False,
                "last line does not match the last written event: log truncated or replaced",
            )
        return True, f"{len(events)} events, chain intact"
