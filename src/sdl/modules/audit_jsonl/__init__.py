"""Audit module that appends events to a hash-chained JSON Lines file.

Each event stores the hash of the event before it, so editing or deleting a
line breaks the chain and ``verify()`` reports where.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from collections import deque
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from pydantic import Field

from sdl.core.models import AuditEvent, AuditFacets, AuditQuery
from sdl.core.module import AuditModule, ModuleConfig

GENESIS = "0" * 64


class JsonlAuditConfig(ModuleConfig):
    path: Path = Field(description="File to append audit events to.")
    fsync: bool = Field(default=True, description="fsync after every event.")


def event_hash(event: AuditEvent) -> str:
    body = event.model_dump(mode="json", exclude={"hash"})
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


class JsonlAuditModule(AuditModule):
    Config = JsonlAuditConfig
    description = "Append-only, hash-chained JSON Lines audit log."
    config: JsonlAuditConfig

    def __init__(self, config: Any, context: Any) -> None:
        super().__init__(config, context)
        self._lock = asyncio.Lock()
        self._last_hash = GENESIS

    async def start(self) -> None:
        path = self.config.path
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            last = None
            with path.open(encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        last = line
            if last:
                self._last_hash = json.loads(last)["hash"]
        else:
            fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)

    async def write(self, event: AuditEvent) -> AuditEvent:
        async with self._lock:
            event.prev_hash = self._last_hash
            event.hash = event_hash(event)
            line = event.model_dump_json() + "\n"
            await asyncio.to_thread(self._append, line)
            self._last_hash = event.hash
            return event

    def _append(self, line: str) -> None:
        with self.config.path.open("a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            if self.config.fsync:
                os.fsync(fh.fileno())

    def _iter(self) -> Iterator[AuditEvent]:
        if not self.config.path.exists():
            return
        with self.config.path.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    yield AuditEvent.model_validate_json(line)

    def _read_all(self) -> list[AuditEvent]:
        return list(self._iter())

    async def query(self, query: AuditQuery) -> list[AuditEvent]:
        def scan() -> list[AuditEvent]:
            matches: deque[AuditEvent] = deque(maxlen=query.limit)
            for event in self._iter():
                if query.matches(event):
                    matches.append(event)
            return list(reversed(matches)) if query.newest_first else list(matches)

        async with self._lock:
            return await asyncio.to_thread(scan)

    async def facets(self) -> AuditFacets:
        def scan() -> AuditFacets:
            facets = AuditFacets()
            for event in self._iter():
                facets.add(event)
            return facets

        async with self._lock:
            return await asyncio.to_thread(scan)

    async def verify(self) -> tuple[bool, str]:
        async with self._lock:
            events = await asyncio.to_thread(self._read_all)
        expected_prev = GENESIS
        for index, event in enumerate(events, start=1):
            if event.prev_hash != expected_prev:
                return (
                    False,
                    f"chain broken at line {index} (event {event.id}): missing or reordered events",
                )
            if event.hash != event_hash(event):
                return False, f"line {index} (event {event.id}) was modified"
            expected_prev = event.hash
        return True, f"{len(events)} events, chain intact"
