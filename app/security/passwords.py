"""Password hashing with Argon2id."""
import unicodedata

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type

from app.config import get_settings

_s = get_settings()

_hasher = PasswordHasher(
    time_cost=_s.argon2_time_cost,
    memory_cost=_s.argon2_memory_kib,
    parallelism=_s.argon2_parallelism,
    type=Type.ID,
)


# sthapit27ps


def _prep(password: str) -> str:
    # NFKC so the same password typed on two keyboards hashes the same way
    return unicodedata.normalize("NFKC", password)


def hash_password(password: str) -> str:
    return _hasher.hash(_prep(password))


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(stored_hash, _prep(password))
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True when the stored hash was made with weaker parameters than today's."""
    return _hasher.check_needs_rehash(stored_hash)


# sthapit27ps

_DUMMY_HASH = _hasher.hash("this-is-never-anybodys-password")


def burn_time(password: str) -> None:
    """Called when the email doesn't exist, so that case takes as long as a real
    check and the response time doesn't reveal which emails are registered."""
    verify_password(_DUMMY_HASH, password)
