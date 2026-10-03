"""Roles and the permissions they grant.

Auth modules and identity providers decide who a caller is; the core maps
them to roles and decides what each role may do, so every IAM provider gets
the same rules. Which *systems* a caller reaches is a separate matter: see
``Access`` in ``sdl.core.models``.
"""

from __future__ import annotations

from sdl.core.models import Actor

ROLLOVER_RUN = "rollover:run"
ROLLOVER_READ = "rollover:read"
TARGETS_READ = "targets:read"
INVENTORY_WRITE = "inventory:write"
AUDIT_READ = "audit:read"
MODULES_READ = "modules:read"
USERS_READ = "users:read"
USERS_WRITE = "users:write"
SELF = "self"
"""Granted to everyone signed in: see who you are, change your own password, set up MFA."""

SUPERUSER_ROLE = "superuser"
"""Held only by the account in the superuser file; cannot be assigned to anyone."""

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    SUPERUSER_ROLE: frozenset(
        {
            ROLLOVER_RUN,
            ROLLOVER_READ,
            TARGETS_READ,
            INVENTORY_WRITE,
            AUDIT_READ,
            MODULES_READ,
            USERS_READ,
            USERS_WRITE,
        }
    ),
    "admin": frozenset(
        {
            ROLLOVER_RUN,
            ROLLOVER_READ,
            TARGETS_READ,
            INVENTORY_WRITE,
            AUDIT_READ,
            MODULES_READ,
            USERS_READ,
            USERS_WRITE,
        }
    ),
    "operator": frozenset({ROLLOVER_RUN, ROLLOVER_READ, TARGETS_READ}),
    "auditor": frozenset({ROLLOVER_READ, TARGETS_READ, AUDIT_READ, USERS_READ}),
}

ASSIGNABLE_ROLES = frozenset(ROLE_PERMISSIONS) - {SUPERUSER_ROLE}


def permissions_of(actor: Actor) -> frozenset[str]:
    granted: set[str] = {SELF}
    for role in actor.roles:
        granted |= ROLE_PERMISSIONS.get(role, frozenset())
    return frozenset(granted)


def allowed(actor: Actor, permission: str) -> bool:
    return permission in permissions_of(actor)


def check_roles(roles: list[str]) -> None:
    unknown = set(roles) - ASSIGNABLE_ROLES
    if unknown:
        raise ValueError(
            f"unknown or unassignable role(s): {', '.join(sorted(unknown))} "
            f"(roles: {', '.join(sorted(ASSIGNABLE_ROLES))})"
        )
