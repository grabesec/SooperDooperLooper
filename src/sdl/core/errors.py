"""Errors the core raises for requests it cannot carry out; the API maps them to HTTP codes."""

from __future__ import annotations


class ConfigError(ValueError):
    pass


class RequestError(ValueError):
    """The caller asked for something that cannot be done (unknown target, busy target...)."""


class NotFoundError(RequestError):
    """The caller named a system, user or inventory that does not exist (or they cannot see)."""


class ConflictError(RequestError):
    """The request clashes with the current state (a busy system, a duplicate name...)."""


class ForbiddenError(RequestError):
    """The caller is signed in but may not do this."""


class AuthenticationError(RequestError):
    """Sign-in failed. ``mfa_required`` means the password was right but a code is needed."""

    def __init__(self, message: str, *, mfa_required: bool = False) -> None:
        super().__init__(message)
        self.mfa_required = mfa_required


class ProviderUnavailableError(RequestError):
    """An identity provider could not be reached or answered with an error."""
