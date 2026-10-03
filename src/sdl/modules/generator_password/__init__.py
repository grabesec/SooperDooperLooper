"""Generates random passwords with the operating system's CSPRNG."""

from __future__ import annotations

import secrets
import string

from pydantic import Field, SecretStr, model_validator

from sdl.core.models import TargetSpec
from sdl.core.module import GeneratorModule, ModuleConfig

AMBIGUOUS = set("Il1O0o")
# Symbols that are safe to pass through shells, chpasswd, config files and URLs
# without quoting surprises. Colons, quotes, backslashes and whitespace are left out.
DEFAULT_SYMBOLS = "!#%+,-.=@^_~"


class PasswordPolicy(ModuleConfig):
    length: int = Field(default=32, ge=12, le=256)
    lowercase: bool = True
    uppercase: bool = True
    digits: bool = True
    symbols: str = Field(default=DEFAULT_SYMBOLS, description="Symbols to use; empty for none.")
    exclude_ambiguous: bool = Field(default=True, description="Leave out Il1O0o.")

    @model_validator(mode="after")
    def _check(self) -> PasswordPolicy:
        forbidden = set(self.symbols) & set(":\n\r\t \\'\"`")
        if forbidden:
            raise ValueError(f"symbols must not include {sorted(forbidden)!r}")
        if not self.classes():
            raise ValueError("the policy must enable at least one character class")
        if len(self.classes()) > self.length:
            raise ValueError("length is too short to include every enabled character class")
        return self

    def classes(self) -> list[str]:
        classes = []
        if self.lowercase:
            classes.append(string.ascii_lowercase)
        if self.uppercase:
            classes.append(string.ascii_uppercase)
        if self.digits:
            classes.append(string.digits)
        if self.symbols:
            classes.append(self.symbols)
        if self.exclude_ambiguous:
            classes = ["".join(c for c in cls if c not in AMBIGUOUS) for cls in classes]
        return [c for c in classes if c]


class PasswordGeneratorModule(GeneratorModule):
    Config = PasswordPolicy
    description = "Random passwords that include every enabled character class."
    config: PasswordPolicy

    def generate(self, target: TargetSpec) -> SecretStr:
        policy = self.config
        if "password_length" in target.options:
            policy = policy.model_copy(update={"length": int(target.options["password_length"])})
            PasswordPolicy.model_validate(policy.model_dump())
        classes = policy.classes()
        alphabet = "".join(classes)
        chars = [secrets.choice(cls) for cls in classes]
        chars += [secrets.choice(alphabet) for _ in range(policy.length - len(chars))]
        secrets.SystemRandom().shuffle(chars)
        return SecretStr("".join(chars))
