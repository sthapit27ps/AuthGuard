import hashlib
from datetime import timedelta

from sqlalchemy import select, update

from app.clock import utcnow
from app.db import SessionLocal
from app.models import AuthSession, LoginAttempt, PasswordHistory, SecurityEvent, User
from tests.conftest import OTHER_PASSWORD, PASSWORD, body, csrf_token, login, post, register, signed_in

# sthapit27ps


# ------------------------------------------------------------ registration


def test_register_then_sign_in_reaches_dashboard(client):
    r = register(client)
    assert r.status_code == 303 and "msg=registered" in r.headers["location"]
    r = login(client)
    assert r.headers["location"] == "/dashboard"
    page = client.get("/dashboard")
    assert page.status_code == 200 and "Sam" in body(page)


def test_password_is_stored_as_argon2id_not_plaintext(client):
    register(client)
    with SessionLocal() as db:
        stored = db.scalar(select(User.password_hash))
    assert stored.startswith("$argon2id$")
    assert PASSWORD not in stored


def test_weak_password_is_refused_with_reasons(client):
    r = register(client, password="password123456")
    assert r.status_code == 400
    assert "common" in body(r)
    with SessionLocal() as db:
        assert db.scalar(select(User.id)) is None


def test_mismatched_confirmation_refused(client):
    r = post(client, "/register", {
        "email": "a@example.com", "display_name": "A", "password": PASSWORD, "confirm": PASSWORD + "x",
    })
    assert r.status_code == 400 and "don't match" in body(r)


def test_duplicate_email_refused(client):
    register(client)
    r = register(client, name="Someone else")
    assert r.status_code == 400 and "already an account" in body(r)


# ------------------------------------------------------------------ login


def test_wrong_password_and_unknown_email_look_identical(client):
    register(client)
    wrong = login(client, password="not-the-right-one-1")
    ghost = login(client, email="nobody@example.com")
    assert wrong.status_code == ghost.status_code == 401
    assert "don't match" in body(wrong) and "don't match" in body(ghost)


def test_lockout_after_five_failures_even_with_correct_password(client):
    register(client)
    for _ in range(4):
        assert login(client, password="wrong-wrong-wrong-1").status_code == 401
    fifth = login(client, password="wrong-wrong-wrong-1")
    assert fifth.status_code == 429  # the fifth failure trips the lock
    assert "Retry-After" in fifth.headers

    blocked = login(client)  # right password, still refused
    assert blocked.status_code == 429
    assert client.get("/dashboard", follow_redirects=False).status_code == 303

    with SessionLocal() as db:
        kinds = set(db.scalars(select(SecurityEvent.kind)))
    assert {"login_failed", "account_locked", "login_blocked"} <= kinds


def test_unknown_email_locks_the_same_way(client):
    for _ in range(5):
        login(client, email="ghost@example.com", password="wrong-wrong-wrong-1")
    assert login(client, email="ghost@example.com").status_code == 429


def test_lock_expires_after_the_window(client):
    register(client)
    for _ in range(5):
        login(client, password="wrong-wrong-wrong-1")
    assert login(client).status_code == 429

    with SessionLocal() as db:  # pretend the failures happened 16 minutes ago
        db.execute(update(LoginAttempt).values(created_at=utcnow() - timedelta(minutes=16)))
        db.commit()
    assert login(client).status_code == 303


def test_success_resets_the_failure_count(client):
    register(client)
    for _ in range(3):
        login(client, password="wrong-wrong-wrong-1")
    assert login(client).status_code == 303
    for _ in range(3):
        login(client, password="wrong-wrong-wrong-1")
    assert login(client).status_code == 303  # 3 + 3 never reached 5 in a row


def test_per_ip_limit(client):
    register(client)
    with SessionLocal() as db:
        for i in range(30):
            db.add(LoginAttempt(kind="login", key=f"x{i}@example.com", ip="testclient", success=False))
        db.commit()
    assert login(client).status_code == 429


# -------------------------------------------------------------------- CSRF


def test_post_without_csrf_token_is_rejected(client):
    register(client)
    r = client.post("/login", data={"email": "sam@example.com", "password": PASSWORD})
    assert r.status_code == 403


def test_forged_csrf_token_is_rejected(client):
    client.get("/login")
    r = client.post("/login", data={"email": "a@b.co", "password": "x", "csrf_token": "0" * 64})
    assert r.status_code == 403


def test_cross_site_origin_is_rejected(client):
    register(client)
    token = csrf_token(client)
    r = client.post(
        "/login",
        data={"email": "sam@example.com", "password": PASSWORD, "csrf_token": token},
        headers={"Origin": "https://evil.example"},
    )
    assert r.status_code == 403


def _login_with_headers(client, **headers):
    register(client)
    token = csrf_token(client)
    return client.post(
        "/login",
        data={"email": "sam@example.com", "password": PASSWORD, "csrf_token": token},
        headers=headers, follow_redirects=False,
    )


def test_browser_fetch_metadata_cross_site_rejected(client):
    r = _login_with_headers(client, **{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"})
    assert r.status_code == 403


def test_same_origin_post_with_null_origin_is_accepted(client):
    # What Chromium really sends on a same-origin form post when the page's
    # Referrer-Policy is strict. This was a real bug caught in the browser.
    r = _login_with_headers(client, **{"Sec-Fetch-Site": "same-origin", "Origin": "null"})
    assert r.status_code == 303


def test_null_origin_without_fetch_metadata_is_rejected(client):
    assert _login_with_headers(client, Origin="null").status_code == 403


def test_referrer_policy_lets_the_browser_send_origin(client):
    assert client.get("/login").headers["referrer-policy"] == "same-origin"


def test_logout_needs_csrf(client):
    signed_in(client)
    assert client.post("/logout").status_code == 403
    assert client.get("/dashboard").status_code == 200  # still signed in


# ---------------------------------------------------------------- sessions


def test_cookie_flags(client):
    register(client)
    r = login(client)
    cookie = next(c for c in r.headers.get_list("set-cookie") if c.startswith("authguard_session="))
    low = cookie.lower()
    assert "httponly" in low and "secure" in low and "samesite=strict" in low


def test_database_never_holds_the_raw_session_token(client):
    signed_in(client)
    token = client.cookies.get("authguard_session")
    with SessionLocal() as db:
        ids = list(db.scalars(select(AuthSession.id)))
    assert token not in ids
    assert hashlib.sha256(token.encode()).hexdigest() in ids


def test_new_token_on_every_login(client):
    signed_in(client)
    first = client.cookies.get("authguard_session")
    login(client)
    assert client.cookies.get("authguard_session") != first


def test_logout_kills_the_session_server_side(client):
    signed_in(client)
    stolen = client.cookies.get("authguard_session")
    r = post(client, "/logout", page="/dashboard")
    assert r.status_code == 303

    client.cookies.clear()
    client.cookies.set("authguard_session", stolen)  # replay the old cookie
    assert client.get("/dashboard", follow_redirects=False).status_code == 303
    with SessionLocal() as db:
        assert db.scalar(select(AuthSession.id)) is None


def test_idle_timeout(client):
    signed_in(client)
    with SessionLocal() as db:
        db.execute(update(AuthSession).values(last_seen_at=utcnow() - timedelta(minutes=31)))
        db.commit()
    r = client.get("/dashboard", follow_redirects=False)
    assert r.status_code == 303 and "expired" in r.headers["location"]


def test_absolute_lifetime(client):
    signed_in(client)
    with SessionLocal() as db:
        db.execute(update(AuthSession).values(expires_at=utcnow() - timedelta(seconds=1)))
        db.commit()
    assert client.get("/dashboard", follow_redirects=False).status_code == 303


def test_protected_pages_redirect_when_signed_out(client):
    for path in ("/dashboard", "/security"):
        r = client.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/login")


def test_security_headers_present(client):
    r = client.get("/login")
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"
    assert "max-age" in r.headers["strict-transport-security"]


def test_no_inline_styles_or_scripts(client):
    # the CSP forbids both, so the templates must not use them
    import re

    signed_in(client)
    for page in ("/login", "/register", "/dashboard", "/security"):
        html = client.get(page).text
        assert " style=" not in html, page
        assert not re.search(r"<script(?![^>]*\bsrc=)", html), page


# --------------------------------------------------------- password change


def test_change_password_blocks_reuse_and_ends_other_sessions(client, make_client):
    signed_in(client)
    other = make_client()
    login(other)
    assert other.get("/dashboard").status_code == 200

    r = post(client, "/security/password", {
        "current_password": PASSWORD, "new_password": OTHER_PASSWORD, "confirm": OTHER_PASSWORD,
    }, page="/security")
    assert r.status_code == 303 and "password_changed" in r.headers["location"]

    assert other.get("/dashboard", follow_redirects=False).status_code == 303  # kicked out
    assert client.get("/dashboard").status_code == 200  # this one stays

    r = post(client, "/security/password", {
        "current_password": OTHER_PASSWORD, "new_password": PASSWORD, "confirm": PASSWORD,
    }, page="/security")
    assert r.status_code == 400 and "recently" in body(r)


def test_change_password_needs_the_current_one(client):
    signed_in(client)
    r = post(client, "/security/password", {
        "current_password": "nope-nope-nope-nope", "new_password": OTHER_PASSWORD, "confirm": OTHER_PASSWORD,
    }, page="/security")
    assert r.status_code == 400 and "isn't right" in body(r)
    with SessionLocal() as db:
        assert db.scalar(select(PasswordHistory.id)) is not None


def test_end_one_session_from_the_devices_list(client, make_client):
    signed_in(client)
    other = make_client()
    login(other)
    with SessionLocal() as db:
        other_id = db.scalar(
            select(AuthSession.id).where(AuthSession.id != hashlib.sha256(
                client.cookies.get("authguard_session").encode()).hexdigest())
        )
    r = post(client, "/security/sessions/end", {"session_id": other_id}, page="/security")
    assert r.status_code == 303
    assert other.get("/dashboard", follow_redirects=False).status_code == 303


# --------------------------------------------------------------------- API


def test_strength_endpoint(client):
    token = csrf_token(client)
    r = client.post("/api/password-strength", json={"password": PASSWORD},
                    headers={"X-CSRF-Token": token})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and body["score"] >= 3

    r = client.post("/api/password-strength", json={"password": "password"},
                    headers={"X-CSRF-Token": token})
    assert r.json()["ok"] is False

    assert client.post("/api/password-strength", json={"password": "x"}).status_code == 403


def test_health(client):
    assert client.get("/healthz").json() == {"status": "ok"}
