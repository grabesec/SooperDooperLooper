"""The superuser file: SDL's one built-in account.

The superuser exists before any user-store or identity-provider module is
configured, so an administrator can always sign in, set up users and recover
from a broken directory connection. Its name and the Argon2id hash of its
password (and, optionally, a TOTP secret) are kept in a small JSON file that
only SDL's own system account may read::

    sdl superuser set -f /etc/sdl/superuser.json --name sdladmin [--totp]

SDL refuses to use the file when other system users can read or change it,
and reads it again on every sign-in, so a reset applies without a restart.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from sdl.core.models import USER_NAME_PATTERN, utcnow

FORMAT_VERSION = 1


class SuperuserFileError(ValueError):
    pass


class Superuser(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = FORMAT_VERSION
    name: str = Field(min_length=1, max_length=255, pattern=USER_NAME_PATTERN)
    display_name: str | None = None
    password_hash: str = Field(min_length=1)
    totp_secret: SecretStr | None = None
    updated_at: datetime = Field(default_factory=utcnow)


def check_permissions(path: Path) -> None:
    """Raise when the file can be read or changed by anyone but its owner, or is owned by
    someone other than SDL's system account (or root)."""
    if sys.platform == "win32":  # pragma: no cover - POSIX permissions only
        return
    try:
        info = path.stat()
    except FileNotFoundError as exc:
        raise SuperuserFileError(
            f"superuser file {path} does not exist; create it with "
            f"'sdl superuser set -f {path} --name <name>'"
        ) from exc
    if not stat.S_ISREG(info.st_mode):
        raise SuperuserFileError(f"superuser file {path} is not a regular file")
    if info.st_mode & 0o077:
        raise SuperuserFileError(
            f"superuser file {path} is accessible to other users (mode "
            f"{stat.S_IMODE(info.st_mode):o}); run 'chmod 600 {path}'"
        )
    if info.st_uid not in (os.geteuid(), 0):
        raise SuperuserFileError(f"superuser file {path} is owned by another user")


def load(path: Path) -> Superuser:
    check_permissions(path)
    try:
        return Superuser.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        raise SuperuserFileError(f"cannot read superuser file {path}: {exc}") from exc


def save(path: Path, superuser: Superuser) -> None:
    """Write the file atomically, readable and writable by its owner only."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = superuser.model_dump(mode="json")
    if superuser.totp_secret is not None:
        data["totp_secret"] = superuser.totp_secret.get_secret_value()
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
