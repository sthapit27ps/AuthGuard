"""Settings, read once from the environment (a .env file is loaded if present)."""
import base64
import os
import secrets
import warnings
from dataclasses import dataclass
from functools import lru_cache

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from dotenv import load_dotenv

load_dotenv()


# sthapit27ps


def _flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _num(name: str, default: int) -> int:
    raw = os.getenv(name)
    return int(raw) if raw not in (None, "") else default


@dataclass(frozen=True)
class Settings:
    env: str
    database_url: str
    secret_key: str
    cookie_secure: bool
    trust_proxy_headers: bool
    session_idle_minutes: int
    session_absolute_hours: int
    mfa_pending_minutes: int
    max_failed_attempts: int
    lockout_minutes: int
    login_ip_limit: int
    ip_window_minutes: int
    argon2_time_cost: int
    argon2_memory_kib: int
    argon2_parallelism: int
    min_password_length: int
    password_history: int

    def derive_key(self, purpose: str) -> bytes:
        """One SECRET_KEY, a separate 32-byte key for each job."""
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=f"authguard:{purpose}".encode(),
        ).derive(self.secret_key.encode())

    def fernet_key(self) -> bytes:
        return base64.urlsafe_b64encode(self.derive_key("totp-at-rest"))


# sthapit27ps


@lru_cache
def get_settings() -> Settings:
    env = os.getenv("AUTHGUARD_ENV", "prod").lower()
    secret = os.getenv("SECRET_KEY", "")

    if len(secret) < 32:
        if env == "prod":
            raise RuntimeError(
                "SECRET_KEY is missing or shorter than 32 characters. Make one with:\n"
                '  python -c "import secrets; print(secrets.token_urlsafe(48))"'
            )
        warnings.warn(
            "No usable SECRET_KEY, using a throwaway one. Sessions and "
            "authenticator secrets will not survive a restart."
        )
        secret = secrets.token_urlsafe(48)

    return Settings(
        env=env,
        database_url=os.getenv("DATABASE_URL", "sqlite:///./authguard.db"),
        secret_key=secret,
        cookie_secure=_flag("COOKIE_SECURE", True),
        trust_proxy_headers=_flag("TRUST_PROXY_HEADERS", False),
        session_idle_minutes=_num("SESSION_IDLE_MINUTES", 30),
        session_absolute_hours=_num("SESSION_ABSOLUTE_HOURS", 12),
        mfa_pending_minutes=_num("MFA_PENDING_MINUTES", 5),
        max_failed_attempts=_num("MAX_FAILED_ATTEMPTS", 5),
        lockout_minutes=_num("LOCKOUT_MINUTES", 15),
        login_ip_limit=_num("LOGIN_IP_LIMIT", 30),
        ip_window_minutes=_num("IP_WINDOW_MINUTES", 10),
        # argon2-cffi defaults follow RFC 9106 (t=3, m=64 MiB, p=4)
        argon2_time_cost=_num("ARGON2_TIME_COST", 3),
        argon2_memory_kib=_num("ARGON2_MEMORY_KIB", 65536),
        argon2_parallelism=_num("ARGON2_PARALLELISM", 4),
        min_password_length=_num("MIN_PASSWORD_LENGTH", 12),
        password_history=_num("PASSWORD_HISTORY", 5),
    )
