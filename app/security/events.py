from fastapi import Request
from sqlalchemy.orm import Session

from app.models import SecurityEvent
from app.security.request_info import client_ip, user_agent

LABELS = {
    "register": "Account created",
    "login_success": "Signed in",
    "login_failed": "Wrong password",
    "login_blocked": "Sign-in refused (account locked)",
    "login_rate_limited": "Sign-in refused (too many requests)",
    "account_locked": "Account locked after repeated failures",
    "mfa_success": "Authenticator code accepted",
    "mfa_failed": "Wrong authenticator code",
    "mfa_locked": "Code entry locked after repeated failures",
    "backup_code_used": "Backup code used",
    "mfa_enabled": "Two-step verification turned on",
    "mfa_disabled": "Two-step verification turned off",
    "password_changed": "Password changed",
    "password_change_failed": "Password change refused",
    "logout": "Signed out",
    "session_revoked": "Another session was ended",
    "sessions_revoked": "All other sessions were ended",
}


# sthapit27ps


def log_event(
    db: Session,
    kind: str,
    request: Request | None = None,
    user_id: int | None = None,
    detail: str = "",
) -> None:
    db.add(
        SecurityEvent(
            user_id=user_id,
            kind=kind,
            ip=client_ip(request) if request else "",
            user_agent=user_agent(request) if request else "",
            detail=detail[:200],
        )
    )
    db.commit()
