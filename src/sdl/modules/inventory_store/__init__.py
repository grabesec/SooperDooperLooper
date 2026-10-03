"""SDL's own inventory: systems kept in a JSON file on the SDL server.

Sysadmins add, change and remove systems through the API (``sdl systems
add``, the web page, ...). Each system records its hostname, FQDN, IP
addresses and the service account SDL signs in with. Credentials are never
stored here: a system only names the secrets-module paths that hold them.

Writes go to a temporary file that then replaces the inventory file, so a
crash never leaves a half-written inventory behind.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from pydantic import Field

from sdl.core.models import TargetSpec
from sdl.core.module import InventoryModule, ModuleConfig, ModuleError

FORMAT_VERSION = 1


class StoreInventoryConfig(ModuleConfig):
    path: Path = Field(description="JSON file holding the inventory; created when missing.")


class StoreInventoryModule(InventoryModule):
    Config = StoreInventoryConfig
    description = "SDL's own inventory of systems, editable through the API."
    writable = True
    config: StoreInventoryConfig

    def __init__(self, config: Any, context: Any) -> None:
        super().__init__(config, context)
        self._lock = asyncio.Lock()
        self._systems: dict[str, TargetSpec] = {}

    async def start(self) -> None:
        path = self.config.path
        if path.exists():
            self._systems = await asyncio.to_thread(self._load)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            await asyncio.to_thread(self._save, {})

    async def health(self) -> dict[str, Any]:
        return {"ok": True, "systems": len(self._systems)}

    def _load(self) -> dict[str, TargetSpec]:
        try:
            data = json.loads(self.config.path.read_text(encoding="utf-8"))
            systems = [TargetSpec.model_validate(s) for s in data.get("systems", [])]
        except (OSError, ValueError) as exc:
            raise ModuleError(f"cannot read inventory {self.config.path}: {exc}") from exc
        return {s.name: s for s in systems}

    def _save(self, systems: dict[str, TargetSpec]) -> None:
        path = self.config.path
        body = {
            "version": FORMAT_VERSION,
            "systems": [_dump(s) for s in sorted(systems.values(), key=lambda s: s.name)],
        }
        fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(body, fh, indent=2)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    async def list_systems(self) -> list[TargetSpec]:
        return [s.model_copy(deep=True) for s in self._systems.values()]

    async def put_system(self, system: TargetSpec) -> None:
        async with self._lock:
            updated = {**self._systems, system.name: system.model_copy(update={"source": None})}
            await asyncio.to_thread(self._save, updated)
            self._systems = updated

    async def delete_system(self, name: str) -> bool:
        async with self._lock:
            if name not in self._systems:
                return False
            updated = {k: v for k, v in self._systems.items() if k != name}
            await asyncio.to_thread(self._save, updated)
            self._systems = updated
            return True

    async def refresh(self) -> None:
        async with self._lock:
            if self.config.path.exists():
                self._systems = await asyncio.to_thread(self._load)


def _dump(system: TargetSpec) -> dict[str, Any]:
    data = system.model_dump(mode="json", exclude={"source"}, exclude_defaults=True)
    derived = system.fqdn or (system.addresses[0] if system.addresses else None) or system.hostname
    if data.get("host") == derived:
        # Keep the address derived, so editing the FQDN or IPs later moves it too.
        del data["host"]
    return data
