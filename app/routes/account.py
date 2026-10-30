from datetime import timedelta

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.clock import utcnow
from app.config import get_settings
from app.db import get_db
from app.deps import Auth, require_auth
from app.models import AuthSession, BackupCode, PasswordHistory, SecurityEvent
from app.security import passwords, policy, sessions, throttle, totp
from app.security.csrf import verify_csrf
from app.security.events import log_event
from app.security.request_info import client_ip
from app.templating import render

router = APIRouter()
_s = get_settings()


# sthapit27ps


def _security_page(request: Request, db: Session, auth: Auth, status: int = 200, **extra):
    user = auth.user
    ctx = {
        "user": user,
        "mfa_state": "on" if user.totp_enabled else ("pending" if user.totp_secret_enc else "off"),
        "sessions": sessions.active_for(db, user.id),
        "current_id": auth.session.id,
        "pw_errors": [],
        "mfa_error": None,
        "min_length": policy.MIN_LENGTH,
    }
    if ctx["mfa_state"] == "pending":
        secret = totp.unseal(user.totp_secret_enc)
        ctx["mfa_secret"] = secret
        ctx["mfa_qr"] = totp.qr_data_uri(totp.provisioning_uri(secret, user.email))
    if ctx["mfa_state"] == "on":
        ctx["codes_left"] = db.scalar(
            select(func.count()).select_from(BackupCode).where(
                BackupCode.user_id == user.id, BackupCode.used_at.is_(None)
            )
        )
    ctx.update(extra)
    return render(request, "security.html", status=status, **ctx)


# --------------------------------------------------------------- dashboard


@router.get("/dashboard")
def dashboard(request: Request, auth: Auth = Depends(require_auth), db: Session = Depends(get_db)):
    events = db.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.user_id == auth.user.id)
        .order_by(SecurityEvent.created_at.desc(), SecurityEvent.id.desc())
        .limit(10)
    ).all()
    return render(
        request, "dashboard.html", user=auth.user, events=events,
        session_count=len(sessions.active_for(db, auth.user.id)),
    )


@router.get("/security")
def security(request: Request, auth: Auth = Depends(require_auth), db: Session = Depends(get_db)):
    return _security_page(request, db, auth)


# --------------------------------------------------------- change password


@router.post("/security/password", dependencies=[Depends(verify_csrf)])
def change_password(
    request: Request,
    current_password: str = Form(""),
    new_password: str = Form(""),
    confirm: str = Form(""),
    auth: Auth = Depends(require_auth),
    db: Session = Depends(get_db),
):
    user, ip = auth.user, client_ip(request)

    # Someone sitting at an unlocked browser shouldn't be able to guess the
    # current password forever, so this gets the same lockout as sign-in.
    wait = throttle.lock_remaining(db, "pwchange", user.email)
    if wait:
        minutes = throttle.minutes_left(wait)
        return _security_page(request, db, auth, status=429, pw_errors=[
            f"Too many wrong passwords. Try again in {minutes} minute{'s' if minutes != 1 else ''}."])

    if not passwords.verify_password(user.password_hash, current_password):
        throttle.record(db, "pwchange", user.email, ip, success=False)
        log_event(db, "password_change_failed", request, user_id=user.id)
        return _security_page(request, db, auth, status=400,
                              pw_errors=["Your current password isn't right."])
    throttle.record(db, "pwchange", user.email, ip, success=True)

    errors: list[str] = []
    if new_password != confirm:
        errors.append("The two new passwords don't match.")
    errors += policy.evaluate(new_password, email=user.email, name=user.display_name).problems

    if not errors:
        recent = db.scalars(
            select(PasswordHistory.password_hash)
            .where(PasswordHistory.user_id == user.id)
            .order_by(PasswordHistory.id.desc())
            .limit(_s.password_history)
        ).all()
        if any(passwords.verify_password(h, new_password) for h in [user.password_hash, *recent]):
            errors.append(f"You've used that password recently. Pick one that's new (the last {_s.password_history} are remembered).")

    if errors:
        return _security_page(request, db, auth, status=400, pw_errors=errors)

    hashed = passwords.hash_password(new_password)
    user.password_hash = hashed
    user.password_changed_at = utcnow()
    db.add(PasswordHistory(user_id=user.id, password_hash=hashed))
    db.commit()

    # keep only the most recent entries
    keep = db.scalars(
        select(PasswordHistory.id).where(PasswordHistory.user_id == user.id)
        .order_by(PasswordHistory.id.desc()).limit(_s.password_history)
    ).all()
    db.execute(delete(PasswordHistory).where(PasswordHistory.user_id == user.id, PasswordHistory.id.not_in(keep)))
    db.commit()

    sessions.destroy_others(db, user.id, keep_id=auth.session.id)
    log_event(db, "password_changed", request, user_id=user.id)
    return RedirectResponse("/security?msg=password_changed", 303)


# --------------------------------------------------------------------- MFA


@router.post("/security/mfa/start", dependencies=[Depends(verify_csrf)])
def mfa_start(request: Request, auth: Auth = Depends(require_auth), db: Session = Depends(get_db)):
    user = auth.user
    if not user.totp_enabled:  # also used for "start over" while a setup is pending
        user.totp_secret_enc = totp.seal(totp.new_secret())
        user.totp_last_step = None
        db.commit()
    return RedirectResponse("/security#two-step", 303)


@router.post("/security/mfa/enable", dependencies=[Depends(verify_csrf)])
def mfa_enable(
    request: Request,
    code: str = Form(""),
    auth: Auth = Depends(require_auth),
    db: Session = Depends(get_db),
):
    user = auth.user
    if user.totp_enabled or not user.totp_secret_enc:
        return RedirectResponse("/security", 303)

    wait = throttle.lock_remaining(db, "mfa", user.email)
    if wait:
        return _security_page(request, db, auth, status=429,
                              mfa_error="Too many wrong codes. Wait a few minutes and try again.")

    ok = totp.check_code(user, code)
    throttle.record(db, "mfa", user.email, client_ip(request), success=ok)
    if not ok:
        return _security_page(request, db, auth, status=400,
                              mfa_error="That code didn't match. Make sure your phone's clock is automatic, then try the next code.")

    user.totp_enabled = True
    db.execute(delete(BackupCode).where(BackupCode.user_id == user.id))
    codes = totp.make_backup_codes()
    for c in codes:
        db.add(BackupCode(user_id=user.id, code_hash=totp.backup_hash(c)))
    db.commit()
    log_event(db, "mfa_enabled", request, user_id=user.id)
    return render(request, "backup_codes.html", user=user, codes=codes)


@router.post("/security/mfa/disable", dependencies=[Depends(verify_csrf)])
def mfa_disable(
    request: Request,
    password: str = Form(""),
    code: str = Form(""),
    auth: Auth = Depends(require_auth),
    db: Session = Depends(get_db),
):
    user, ip = auth.user, client_ip(request)
    if not user.totp_enabled:
        return RedirectResponse("/security", 303)

    wait = throttle.lock_remaining(db, "mfa", user.email)
    if wait:
        return _security_page(request, db, auth, status=429,
                              mfa_error="Too many wrong attempts. Wait a few minutes and try again.")

    # Turning protection off needs both factors again, not just the open session.
    # Password first: a wrong password must not use up a good code.
    pw_ok = passwords.verify_password(user.password_hash, password)
    code_ok = pw_ok and totp.check_code(user, code)
    throttle.record(db, "mfa", user.email, ip, success=pw_ok and code_ok)
    if not (pw_ok and code_ok):
        return _security_page(request, db, auth, status=400,
                              mfa_error="Password or code was wrong. Both are needed to turn this off.")

    user.totp_enabled = False
    user.totp_secret_enc = None
    user.totp_last_step = None
    db.execute(delete(BackupCode).where(BackupCode.user_id == user.id))
    db.commit()
    log_event(db, "mfa_disabled", request, user_id=user.id)
    return RedirectResponse("/security?msg=mfa_disabled", 303)


# ---------------------------------------------------------------- sessions


@router.post("/security/sessions/end", dependencies=[Depends(verify_csrf)])
def end_session(
    request: Request,
    session_id: str = Form(""),
    auth: Auth = Depends(require_auth),
    db: Session = Depends(get_db),
):
    row = db.get(AuthSession, session_id)
    if row and row.user_id == auth.user.id and row.id != auth.session.id:
        sessions.destroy(db, row)
        log_event(db, "session_revoked", request, user_id=auth.user.id)
    return RedirectResponse("/security?msg=session_ended#devices", 303)


@router.post("/security/sessions/end-others", dependencies=[Depends(verify_csrf)])
def end_other_sessions(request: Request, auth: Auth = Depends(require_auth), db: Session = Depends(get_db)):
    sessions.destroy_others(db, auth.user.id, keep_id=auth.session.id)
    log_event(db, "sessions_revoked", request, user_id=auth.user.id)
    return RedirectResponse("/security?msg=others_ended#devices", 303)
