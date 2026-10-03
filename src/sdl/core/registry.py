"""Finds module classes by type name."""

from __future__ import annotations

import importlib
from importlib.metadata import entry_points

from sdl.core.module import Module

ENTRY_POINT_GROUP = "sdl.modules"


class UnknownModuleError(LookupError):
    pass


class ModuleRegistry:
    """Maps module type names (``target.ssh_linux``) to module classes.

    Types come from the ``sdl.modules`` entry-point group. A type can also be
    given as ``package.module:ClassName``, which is handy while developing a
    module that is not packaged yet.
    """

    def __init__(self) -> None:
        self._types: dict[str, type[Module]] = {}

    @classmethod
    def from_entry_points(cls) -> ModuleRegistry:
        registry = cls()
        for ep in entry_points(group=ENTRY_POINT_GROUP):
            registry._types[ep.name] = _check(ep.name, ep.load())
        return registry

    def register(self, type_name: str, module_cls: type[Module]) -> None:
        self._types[type_name] = _check(type_name, module_cls)

    def available(self) -> dict[str, type[Module]]:
        return dict(sorted(self._types.items()))

    def resolve(self, type_name: str) -> type[Module]:
        if type_name in self._types:
            return self._types[type_name]
        if ":" in type_name:
            module_path, _, attr = type_name.partition(":")
            return _check(type_name, getattr(importlib.import_module(module_path), attr))
        known = ", ".join(self._types) or "none"
        raise UnknownModuleError(f"unknown module type {type_name!r} (installed: {known})")


def _check(name: str, obj: object) -> type[Module]:
    if not (isinstance(obj, type) and issubclass(obj, Module)):
        raise TypeError(f"module type {name!r} does not point to a Module subclass")
    return obj
