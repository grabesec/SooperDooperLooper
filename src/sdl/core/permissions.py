"""Roles and the permissions they grant.

Auth modules decide who a caller is and which roles they hold; the core
decides what each role may do, so every IAM provider gets the same rules.
"""

from __future__ import annotations

from sdl.core.models import Actor

ROLLOVER_RUN = "rollover:run"
ROLLOVER_READ = "rollover:read"
TARGETS_READ = "targets:read"
INVENTORY_WRITE = "inventory:write"
AUDIT_READ = "audit:read"
MODULES_READ = "modules:read"

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "admin": frozenset(
        {ROLLOVER_RUN, ROLLOVER_READ, TARGETS_READ, INVENTORY_WRITE, AUDIT_READ, MODULES_READ}
    ),
    "operator": frozenset({ROLLOVER_RUN, ROLLOVER_READ, TARGETS_READ}),
    "auditor": frozenset({ROLLOVER_READ, TARGETS_READ, AUDIT_READ}),
}


def allowed(actor: Actor, permission: str) -> bool:
    return any(permission in ROLE_PERMISSIONS.get(role, frozenset()) for role in actor.roles)
