"""Bearer-token authentication from a static list of API clients.

Only SHA-256 hashes of the tokens are kept in the configuration. Generate a
token and its hash with ``sdl token new``. It is meant for machine clients
(scripts, CI jobs, the MCP server); people sign in as users instead (see
docs/users.md).
"""

from __future__ import annotations

import hashlib
import hmac
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, model_validator

from sdl.core.models import Access, Actor, ActorType
from sdl.core.module import AuthModule, ModuleConfig
from sdl.core.permissions import check_roles

if TYPE_CHECKING:
    from fastapi import Request


class TokenClient(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    display_name: str | None = None
    token_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    roles: list[str] = Field(default_factory=lambda: ["operator"])
    type: ActorType = ActorType.USER
    access: Access | None = Field(
        default=None,
        description="Inventory groups and systems this client reaches; every system when unset.",
    )


class StaticTokenConfig(ModuleConfig):
    clients: list[TokenClient] = Field(min_length=1)

    @model_validator(mode="after")
    def _known_roles(self) -> StaticTokenConfig:
        check_roles([r for c in self.clients for r in c.roles])
        return self


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class StaticTokenAuthModule(AuthModule):
    Config = StaticTokenConfig
    description = "Bearer tokens listed (as hashes) in the configuration."
    config: StaticTokenConfig

    async def authenticate(self, request: Request) -> Actor | None:
        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            return None
        digest = hash_token(token.strip())
        for client in self.config.clients:
            if hmac.compare_digest(digest, client.token_sha256):
                return Actor(
                    type=client.type,
                    id=client.id,
                    display_name=client.display_name,
                    roles=list(client.roles),
                    access=client.access,
                )
        return None
