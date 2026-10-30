import re
from datetime import timedelta

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.models import BackupCode, PasswordHistory, User
from app.clock import utcnow
from app.security import passwords, policy, sessions, throttle, totp
from app.security.csrf import verify_csrf
from app.security.events import log_event
from app.security.request_info import client_ip
from app.templating import render

router = APIRouter()
_s = get_settings()

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# sthapit27ps


def normalize_email(value: str) -> str:
    return value.strip().lower()[:254]


def _signed_in(request: Request, db: Session) -> bool:
    row = sessions.load(db, request)
    return row is not None and not row.mfa_pending


def _too_many(request: Request, message: str, seconds: int):
    return render(
        request, "error.html", status=429, title="Too many attempts",
        message=message, headers={"Retry-After": str(seconds)},
    )


@router.get("/", include_in_schema=False)
def home(request: Request, db: Session = Depends(get_db)):
    return RedirectResponse("/dashboard" if _signed_in(request, db) else "/login", 303)


# ---------------------------------------------------------------- register


@router.get("/register")
def register_page(request: Request, db: Session = Depends(get_db)):
    if _signed_in(request, db):
        return RedirectResponse("/dashboard", 303)
    return render(request, "register.html", form={}, errors=[])


@router.post("/register", dependencies=[Depends(verify_csrf)])
def register(
    request: Request,
    email: str = Form(""),
    display_name: str = Form(""),
    password: str = Form(""),
    confirm: str = Form(""),
    db: Session = Depends(get_db),
):
    ip = client_ip(request)
    if throttle.ip_over_limit(db, "register", ip, limit=10, window=timedelta(hours=1)):
        return _too_many(request, "That's a lot of sign-ups from one address. Try again in an hour.", 3600)

    email = normalize_email(email)
    name = display_name.strip()[:80] or email.split("@")[0]
    errors: list[str] = []

    if not EMAIL_RE.match(email):
        errors.append("That doesn't look like an email address.")
    if password != confirm:
        errors.append("The two passwords don't match.")
    errors += policy.evaluate(password, email=email, name=name).problems

    if not errors and db.scalar(select(User.id).where(User.email == email)):
        errors.append("There's already an account with that email. Try signing in.")

    if not errors:
        hashed = passwords.hash_password(password)
        user = User(email=email, display_name=name, password_hash=hashed)
        db.add(user)
        try:
            db.flush()
        except IntegrityError:  # someone registered the same email a moment ago
            db.rollback()
            errors.append("There's already an account with that email. Try signing in.")
        else:
            db.add(PasswordHistory(user_id=user.id, password_hash=hashed))
            db.commit()

    throttle.record(db, "register", "-", ip, success=not errors)
    if errors:
        form = {"email": email, "display_name": display_name}
        return render(request, "register.html", status=400, form=form, errors=errors)

    log_event(db, "register", request, user_id=user.id)
    return RedirectResponse("/login?msg=registered", 303)


# ------------------------------------------------------------------- login


@router.get("/login")
def login_page(request: Request, db: Session = Depends(get_db)):
    if _signed_in(request, db):
        return RedirectResponse("/dashboard", 303)
    return render(request, "login.html", email="", error=None)


def _finish_login(db: Session, request: Request, user: User):
    token, _row, max_age = sessions.create(db, user, request)
    log_event(db, "login_success", request, user_id=user.id)
    throttle.prune(db)
    response = RedirectResponse("/dashboard", 303)
    sessions.set_cookie(response, token, max_age)
    return response


@router.post("/login", dependencies=[Depends(verify_csrf)])
def login(
    request: Request,
    email: str = Form(""),
    password: str = Form(""),
    db: Session = Depends(get_db),
):
    ip = client_ip(request)
    key = normalize_email(email)

    if throttle.ip_over_limit(db, "login", ip):
        log_event(db, "login_rate_limited", request)
        return _too_many(request, "Too many sign-in attempts from this address. Wait a few minutes and try again.", 600)

    wait = throttle.lock_remaining(db, "login", key)
    if wait:
        user = db.scalar(select(User).where(User.email == key))
        log_event(db, "login_blocked", request, user_id=user.id if user else None)
        minutes = throttle.minutes_left(wait)
        return _too_many(
            request,
            f"Too many wrong passwords for this email. You can try again in {minutes} minute{'s' if minutes != 1 else ''}.",
            int(wait.total_seconds()),
        )

    user = db.scalar(select(User).where(User.email == key))
    if user is None:
        passwords.burn_time(password)  # same cost as a real check
        ok = False
    else:
        ok = passwords.verify_password(user.password_hash, password)

    if not ok:
        throttle.record(db, "login", key, ip, success=False)
        if user:
            log_event(db, "login_failed", request, user_id=user.id)
        wait = throttle.lock_remaining(db, "login", key)
        if wait:
            if user:
                log_event(db, "account_locked", request, user_id=user.id)
            minutes = throttle.minutes_left(wait)
            return _too_many(
                request,
                f"Too many wrong passwords for this email. You can try again in {minutes} minute{'s' if minutes != 1 else ''}.",
                int(wait.total_seconds()),
            )
        return render(request, "login.html", status=401, email=key,
                      error="That email and password don't match.")

    throttle.record(db, "login", key, ip, success=True)
    if passwords.needs_rehash(user.password_hash):
        user.password_hash = passwords.hash_password(password)
        db.commit()

    # Whatever session cookie came with this request is finished.
    old = sessions.load(db, request)
    if old:
        sessions.destroy(db, old)

    if user.totp_enabled:
        token, _row, max_age = sessions.create(db, user, request, mfa_pending=True)
        response = RedirectResponse("/login/mfa", 303)
        sessions.set_cookie(response, token, max_age)
        return response
    return _finish_login(db, request, user)


# --------------------------------------------------------- second step (MFA)


def _pending(request: Request, db: Session):
    row = sessions.load(db, request)
    if row is None or not row.mfa_pending:
        return None, None
    return row, db.get(User, row.user_id)


@router.get("/login/mfa")
def mfa_page(request: Request, db: Session = Depends(get_db)):
    row, user = _pending(request, db)
    if row is None:
        return RedirectResponse("/login", 303)
    return render(request, "mfa_challenge.html", error=None)


@router.post("/login/mfa", dependencies=[Depends(verify_csrf)])
def mfa_submit(request: Request, code: str = Form(""), db: Session = Depends(get_db)):
    row, user = _pending(request, db)
    if row is None or user is None:
        return RedirectResponse("/login", 303)

    ip = client_ip(request)
    wait = throttle.lock_remaining(db, "mfa", user.email)
    if wait:
        sessions.destroy(db, row)
        log_event(db, "mfa_locked", request, user_id=user.id)
        minutes = throttle.minutes_left(wait)
        response = _too_many(
            request,
            f"Too many wrong codes. You can try again in {minutes} minute{'s' if minutes != 1 else ''}.",
            int(wait.total_seconds()),
        )
        sessions.clear_cookie(response)
        return response

    used_backup = False
    ok = False
    if totp.looks_like_backup_code(code):
        digest = totp.backup_hash(code)
        match = db.scalar(
            select(BackupCode).where(
                BackupCode.user_id == user.id,
                BackupCode.code_hash == digest,
                BackupCode.used_at.is_(None),
            )
        )
        if match:
            match.used_at = utcnow()
            db.commit()
            ok = used_backup = True
    else:
        ok = totp.check_code(user, code)
        if ok:
            db.commit()  # keeps the "window already used" marker

    throttle.record(db, "mfa", user.email, ip, success=ok)
    if not ok:
        log_event(db, "mfa_failed", request, user_id=user.id)
        return render(request, "mfa_challenge.html", status=401,
                      error="That code didn't work. Check the code in your app and try again.")

    sessions.destroy(db, row)  # the pending session is spent; issue a fresh one
    log_event(db, "backup_code_used" if used_backup else "mfa_success", request, user_id=user.id)
    return _finish_login(db, request, user)


# ------------------------------------------------------------------ logout


@router.post("/logout", dependencies=[Depends(verify_csrf)])
def logout(request: Request, db: Session = Depends(get_db)):
    row = sessions.load(db, request)
    if row:
        if not row.mfa_pending:
            log_event(db, "logout", request, user_id=row.user_id)
        sessions.destroy(db, row)
    response = RedirectResponse("/login?msg=signed_out", 303)
    sessions.clear_cookie(response)
    return response
