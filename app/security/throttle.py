"""Failed-attempt tracking, lockouts and per-IP limits."""
import time
from collections import deque
from datetime import timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.clock import utcnow
from app.config import get_settings
from app.models import AuthSession, LoginAttempt

_s = get_settings()


def record(db: Session, kind: str, key: str, ip: str, success: bool) -> None:
    db.add(LoginAttempt(kind=kind, key=key[:254], ip=ip, success=success))
    db.commit()


# sthapit27ps


def lock_remaining(db: Session, kind: str, key: str) -> timedelta | None:
    """How long `key` (an email) stays locked, or None if it isn't.

    Locked means: MAX_FAILED_ATTEMPTS failures inside the last LOCKOUT_MINUTES,
    counting only failures after the most recent success. Because this is worked
    out from the attempts table and not from the user row, an email that doesn't
    exist locks the same way as one that does."""
    now = utcnow()
    window = timedelta(minutes=_s.lockout_minutes)

    last_ok = db.scalar(
        select(func.max(LoginAttempt.created_at)).where(
            LoginAttempt.kind == kind, LoginAttempt.key == key, LoginAttempt.success.is_(True)
        )
    )
    since = now - window
    if last_ok is not None and last_ok > since:
        since = last_ok

    fails = db.scalars(
        select(LoginAttempt.created_at)
        .where(
            LoginAttempt.kind == kind,
            LoginAttempt.key == key,
            LoginAttempt.success.is_(False),
            LoginAttempt.created_at > since,
        )
        .order_by(LoginAttempt.created_at)
    ).all()

    if len(fails) >= _s.max_failed_attempts:
        until = fails[len(fails) - _s.max_failed_attempts] + window
        if until > now:
            return until - now
    return None


def ip_over_limit(
    db: Session, kind: str, ip: str, limit: int | None = None, window: timedelta | None = None
) -> bool:
    limit = limit if limit is not None else _s.login_ip_limit
    window = window or timedelta(minutes=_s.ip_window_minutes)
    count = db.scalar(
        select(func.count())
        .select_from(LoginAttempt)
        .where(
            LoginAttempt.kind == kind,
            LoginAttempt.ip == ip,
            LoginAttempt.created_at > utcnow() - window,
        )
    )
    return (count or 0) >= limit


def minutes_left(delta: timedelta) -> int:
    return max(1, int(-(-delta.total_seconds() // 60)))


def prune(db: Session) -> None:
    """Housekeeping: drop old attempts and dead sessions."""
    db.execute(delete(LoginAttempt).where(LoginAttempt.created_at < utcnow() - timedelta(days=2)))
    db.execute(delete(AuthSession).where(AuthSession.expires_at < utcnow()))
    db.commit()


# sthapit27ps


class MemoryLimiter:
    """Tiny in-process sliding window. Only used for the password-strength
    endpoint, which is hit often and isn't worth a database write each time.
    It is per worker process, which is fine for that job."""

    def __init__(self) -> None:
        self._hits: dict[str, deque] = {}

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        q = self._hits.setdefault(key, deque())
        while q and now - q[0] > window_seconds:
            q.popleft()
        if len(self._hits) > 5000:
            self._hits = {k: v for k, v in self._hits.items() if v}
        if len(q) >= limit:
            return False
        q.append(now)
        return True


strength_limiter = MemoryLimiter()
