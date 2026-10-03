"""Password hashing (Argon2id) and the password policy.

SDL never stores a password, only its Argon2id hash (RFC 9106), for the
superuser file and for local users alike.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher()
# Checked when the user is unknown, so a wrong name costs as long as a wrong password.
_DUMMY_HASH = _hasher.hash("sdl-no-such-user")

MAX_PASSWORD_LENGTH = 1024


class PasswordPolicyError(ValueError):
    pass


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    """True when ``password`` matches; always takes about as long, even without a hash."""
    if not password or len(password) > MAX_PASSWORD_LENGTH:
        return False
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and bool(password_hash)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return False


def check_policy(password: str, min_length: int, *, name: str | None = None) -> None:
    """Raise ``PasswordPolicyError`` when ``password`` is too weak to accept."""
    if len(password) < min_length:
        raise PasswordPolicyError(f"the password must be at least {min_length} characters long")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"the password must be at most {MAX_PASSWORD_LENGTH} characters")
    if len(set(password)) < 4:
        raise PasswordPolicyError("the password repeats too few different characters")
    if name and name.lower() in password.lower():
        raise PasswordPolicyError("the password must not contain the user name")
