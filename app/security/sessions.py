"""Server-side sessions. The cookie holds a random token; the database holds
only its SHA-256, plus when the session started, was last used and expires."""
import hashlib
import secrets
from datetime import timedelta

from fastapi import Request, Response
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.clock import utcnow
from app.config import get_settings
from app.models import AuthSession, User
from app.security.request_info import client_ip, user_agent

_s = get_settings()

COOKIE_NAME = "authguard_session"


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# sthapit27ps


def create(db: Session, user: User, request: Request, *, mfa_pending: bool = False) -> tuple[str, AuthSession, int]:
    """Always a brand-new token on every sign-in, so a token planted before
    login is worthless afterwards. Returns (token, row, cookie max-age seconds)."""
    token = secrets.token_urlsafe(32)
    now = utcnow()
    lifetime = (
        timedelta(minutes=_s.mfa_pending_minutes)
        if mfa_pending
        else timedelta(hours=_s.session_absolute_hours)
    )
    row = AuthSession(
        id=_digest(token),
        user_id=user.id,
        created_at=now,
        last_seen_at=now,
        expires_at=now + lifetime,
        mfa_pending=mfa_pending,
        ip=client_ip(request),
        user_agent=user_agent(request),
    )
    db.add(row)
    db.commit()
    return token, row, int(lifetime.total_seconds())


def set_cookie(response: Response, token: str, max_age: int) -> None:
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=max_age,
        httponly=True,  # page scripts can't read it
        secure=_s.cookie_secure,  # HTTPS only
        samesite="strict",  # never sent on cross-site requests
        path="/",
    )


def clear_cookie(response: Response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/", httponly=True, secure=_s.cookie_secure, samesite="strict")


def load(db: Session, request: Request) -> AuthSession | None:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    row = db.get(AuthSession, _digest(token))
    if row is None:
        return None

    now = utcnow()
    idle_deadline = row.last_seen_at + timedelta(minutes=_s.session_idle_minutes)
    expired = row.expires_at <= now or (not row.mfa_pending and idle_deadline <= now)
    if expired:
        db.delete(row)
        db.commit()
        return None

    # Only write last_seen once a minute. Costs up to a minute of idle accuracy,
    # saves a database write on every request.
    if (now - row.last_seen_at).total_seconds() > 60:
        row.last_seen_at = now
        db.commit()
    return row


def destroy(db: Session, row: AuthSession) -> None:
    db.delete(row)
    db.commit()


def destroy_others(db: Session, user_id: int, keep_id: str | None = None) -> None:
    stmt = delete(AuthSession).where(AuthSession.user_id == user_id)
    if keep_id:
        stmt = stmt.where(AuthSession.id != keep_id)
    db.execute(stmt)
    db.commit()


def active_for(db: Session, user_id: int) -> list[AuthSession]:
    return list(
        db.scalars(
            select(AuthSession)
            .where(
                AuthSession.user_id == user_id,
                AuthSession.mfa_pending.is_(False),
                AuthSession.expires_at > utcnow(),
            )
            .order_by(AuthSession.last_seen_at.desc())
        )
    )
