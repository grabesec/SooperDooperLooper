"""SDL's own user store: users kept in a JSON file on the SDL server.

It holds local accounts (with their Argon2id password hashes and TOTP
secrets) and the records of users who sign in through an identity provider.
The file is written atomically and only its owner may read it: SDL refuses
to start when other system users can.
"""

from __future__ import annotations

import asyncio
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

from pydantic import Field

from sdl.core.models import UserRecord
from sdl.core.module import ModuleConfig, ModuleError, UserStoreModule

FORMAT_VERSION = 1


class StoreUsersConfig(ModuleConfig):
    path: Path = Field(description="JSON file holding the users; created when missing.")


class StoreUsersModule(UserStoreModule):
    Config = StoreUsersConfig
    description = "SDL's own users, kept in a file only SDL can read."
    config: StoreUsersConfig

    def __init__(self, config: Any, context: Any) -> None:
        super().__init__(config, context)
        self._lock = asyncio.Lock()
        self._users: dict[str, UserRecord] = {}

    async def start(self) -> None:
        path = self.config.path
        if path.exists():
            self._check_permissions()
            self._users = await asyncio.to_thread(self._load)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            await asyncio.to_thread(self._save, {})

    async def health(self) -> dict[str, Any]:
        return {"ok": True, "users": len(self._users)}

    def _check_permissions(self) -> None:
        if sys.platform == "win32":  # pragma: no cover - POSIX permissions only
            return
        mode = stat.S_IMODE(self.config.path.stat().st_mode)
        if mode & 0o077:
            raise ModuleError(
                f"user file {self.config.path} is accessible to other users (mode {mode:o}); "
                f"run 'chmod 600 {self.config.path}'"
            )

    def _load(self) -> dict[str, UserRecord]:
        try:
            data = json.loads(self.config.path.read_text(encoding="utf-8"))
            users = [UserRecord.model_validate(u) for u in data.get("users", [])]
        except (OSError, ValueError) as exc:
            raise ModuleError(f"cannot read users {self.config.path}: {exc}") from exc
        return {u.name: u for u in users}

    def _save(self, users: dict[str, UserRecord]) -> None:
        path = self.config.path
        body = {
            "version": FORMAT_VERSION,
            "users": [_dump(u) for u in sorted(users.values(), key=lambda u: u.name)],
        }
        fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(body, fh, indent=2)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    async def list_users(self) -> list[UserRecord]:
        return [u.model_copy(deep=True) for u in self._users.values()]

    async def get_user(self, name: str) -> UserRecord | None:
        user = self._users.get(name.lower())
        return user.model_copy(deep=True) if user else None

    async def put_user(self, user: UserRecord) -> None:
        async with self._lock:
            updated = {**self._users, user.name: user.model_copy(deep=True)}
            await asyncio.to_thread(self._save, updated)
            self._users = updated

    async def delete_user(self, name: str) -> bool:
        async with self._lock:
            name = name.lower()
            if name not in self._users:
                return False
            updated = {k: v for k, v in self._users.items() if k != name}
            await asyncio.to_thread(self._save, updated)
            self._users = updated
            return True


def _dump(user: UserRecord) -> dict[str, Any]:
    data = user.model_dump(mode="json", exclude_none=True)
    if user.totp_secret is not None:
        data["totp_secret"] = user.totp_secret.get_secret_value()
    return data
