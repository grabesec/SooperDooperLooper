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


class ApiSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    auth: str | None = Field(
        default=None, description="Auth module instance id; defaults to the only one."
    )


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    modules: dict[str, ModuleInstanceSettings]
    targets: list[TargetSpec] = Field(default_factory=list)
    rollover: RolloverSettings = Field(default_factory=RolloverSettings)
    api: ApiSettings = Field(default_factory=ApiSettings)

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
