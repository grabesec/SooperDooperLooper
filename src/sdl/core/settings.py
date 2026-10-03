"""SDL's configuration file (``sdl.yaml``)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from sdl.core.models import TargetSpec


class ModuleInstanceSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str = Field(description="Module type, e.g. 'target.ssh_linux'.")
    config: dict[str, Any] = Field(default_factory=dict)


class RolloverSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_parallel: int = Field(default=5, ge=1, le=100)
    generator: str | None = Field(
        default=None, description="Generator module instance id; defaults to the only one."
    )
    shutdown_grace: float = Field(
        default=300, ge=0, description="Seconds to let running rollovers finish on shutdown."
    )
    staging_suffix: str = Field(
        default="__sdl_pending",
        description=(
            "A new credential is escrowed at '<secret_path>/<staging_suffix>' before it is set on "
            "the target, so it is never lost if a later step fails."
        ),
    )


class InventorySettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timeout: float = Field(
        default=30, gt=0, description="Seconds to wait for an inventory module to list its systems."
    )


class ApiSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    auth: str | None = Field(
        default=None,
        description="Only accept API tokens from this auth module; by default every configured "
        "auth module is asked in turn.",
    )
    public_url: str | None = Field(
        default=None,
        description="Address browsers reach SDL at (https://sdl.example.com); needed for "
        "single sign-on callbacks behind a reverse proxy. Defaults to the request's own URL.",
    )


class IdentitySettings(BaseModel):
    """Who can sign in, and how: the superuser, users, sessions and sign-in protection."""

    model_config = ConfigDict(extra="forbid")

    superuser_file: Path | None = Field(
        default=None,
        description="JSON file with the superuser's name and password hash; create it with "
        "'sdl superuser set'. Only SDL's system account may be able to read it.",
    )
    users: str | None = Field(
        default=None, description="User-store module instance id; defaults to the only one."
    )
    session_ttl: float = Field(
        default=8 * 3600, gt=0, description="Seconds a sign-in lasts at most."
    )
    session_idle: float = Field(
        default=3600, gt=0, description="Seconds of inactivity after which a sign-in ends."
    )
    password_min_length: int = Field(default=12, ge=8, le=1024)
    require_mfa: bool = Field(
        default=False,
        description="Local users must set up a TOTP authenticator before they can do anything.",
    )
    max_failed_logins: int = Field(
        default=5, ge=1, description="Failed sign-ins in a row before the account is locked."
    )
    lockout: float = Field(
        default=900, ge=0, description="Seconds an account stays locked after too many failures."
    )


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    modules: dict[str, ModuleInstanceSettings]
    targets: list[TargetSpec] = Field(
        default_factory=list,
        description="Systems listed directly in the configuration; inventory modules add more.",
    )
    inventory: InventorySettings = Field(default_factory=InventorySettings)
    rollover: RolloverSettings = Field(default_factory=RolloverSettings)
    api: ApiSettings = Field(default_factory=ApiSettings)
    identity: IdentitySettings = Field(default_factory=IdentitySettings)

    @model_validator(mode="after")
    def _unique_target_names(self) -> Settings:
        seen: set[str] = set()
        for target in self.targets:
            if target.name in seen:
                raise ValueError(f"duplicate target name {target.name!r}")
            seen.add(target.name)
        return self

    @classmethod
    def load(cls, path: str | Path) -> Settings:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return cls.model_validate(data)
