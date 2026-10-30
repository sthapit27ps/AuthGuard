import re
import time

import pyotp
from sqlalchemy import select

from app.db import SessionLocal
from app.models import BackupCode, User
from app.security import totp
from tests.conftest import PASSWORD, login, post, signed_in

# sthapit27ps


def code_for(secret, offset=0):
    """A valid code for the current 30-second window plus `offset` windows."""
    return pyotp.TOTP(secret).generate_otp(int(time.time()) // 30 + offset)


def turn_on_mfa(client):
    """Walk the real setup flow. Returns (secret, backup_codes)."""
    signed_in(client)
    post(client, "/security/mfa/start", page="/security")
    secret = re.search(r'class="secret mono">([A-Z2-7]+)<', client.get("/security").text).group(1)
    r = post(client, "/security/mfa/enable", {"code": code_for(secret)}, page="/security")
    assert r.status_code == 200 and "only time" in r.text
    codes = re.findall(r"<li>([a-z0-9]{5}-[a-z0-9]{5})</li>", r.text)
    assert len(codes) == 8
    return secret, codes


def fresh_login(client):
    client.cookies.clear()
    return login(client)


def test_secret_is_encrypted_at_rest(client):
    secret, _ = turn_on_mfa(client)
    with SessionLocal() as db:
        stored = db.scalar(select(User.totp_secret_enc))
    assert stored and secret not in stored
    assert totp.unseal(stored) == secret


def test_backup_codes_are_not_stored_in_clear(client):
    _, codes = turn_on_mfa(client)
    with SessionLocal() as db:
        hashes = set(db.scalars(select(BackupCode.code_hash)))
    assert len(hashes) == 8
    assert not any(c.replace("-", "") in h for c in codes for h in hashes)


def test_password_alone_no_longer_signs_in(client):
    secret, _ = turn_on_mfa(client)
    r = fresh_login(client)
    assert r.headers["location"] == "/login/mfa"
    # half-signed-in: protected pages still refuse
    assert client.get("/dashboard", follow_redirects=False).status_code == 303
    assert client.get("/security", follow_redirects=False).status_code == 303


def test_correct_code_completes_sign_in(client):
    secret, _ = turn_on_mfa(client)
    fresh_login(client)
    # the setup consumed the current window, so use the next one (allowed as drift)
    r = post(client, "/login/mfa", {"code": code_for(secret, +1)}, page="/login/mfa")
    assert r.status_code == 303 and r.headers["location"] == "/dashboard"
    assert client.get("/dashboard").status_code == 200


def test_wrong_code_is_refused(client):
    turn_on_mfa(client)
    fresh_login(client)
    r = post(client, "/login/mfa", {"code": "000000"}, page="/login/mfa")
    assert r.status_code == 401
    assert client.get("/dashboard", follow_redirects=False).status_code == 303


def test_a_used_code_cannot_be_replayed(client):
    secret, _ = turn_on_mfa(client)
    good = code_for(secret, +1)

    fresh_login(client)
    assert post(client, "/login/mfa", {"code": good}, page="/login/mfa").status_code == 303

    fresh_login(client)
    assert post(client, "/login/mfa", {"code": good}, page="/login/mfa").status_code == 401


def test_the_enabling_code_cannot_be_reused_to_sign_in(client):
    secret, _ = turn_on_mfa(client)
    fresh_login(client)
    r = post(client, "/login/mfa", {"code": code_for(secret)}, page="/login/mfa")
    assert r.status_code == 401


def test_backup_code_works_exactly_once(client):
    _, codes = turn_on_mfa(client)

    fresh_login(client)
    assert post(client, "/login/mfa", {"code": codes[0]}, page="/login/mfa").status_code == 303

    fresh_login(client)
    assert post(client, "/login/mfa", {"code": codes[0]}, page="/login/mfa").status_code == 401

    fresh_login(client)
    assert post(client, "/login/mfa", {"code": codes[1].upper()}, page="/login/mfa").status_code == 303


def test_code_guessing_is_locked_out(client):
    secret, _ = turn_on_mfa(client)
    fresh_login(client)
    for _ in range(5):
        post(client, "/login/mfa", {"code": "111111"}, page="/login/mfa")
    r = post(client, "/login/mfa", {"code": code_for(secret, +1)}, page="/login/mfa")
    assert r.status_code == 429  # even the right code is refused while locked


def test_turning_off_needs_password_and_code(client):
    secret, _ = turn_on_mfa(client)

    r = post(client, "/security/mfa/disable", {"password": PASSWORD, "code": "000000"}, page="/security")
    assert r.status_code == 400
    r = post(client, "/security/mfa/disable", {"password": "wrong-wrong-wrong-1", "code": code_for(secret, +1)}, page="/security")
    assert r.status_code == 400

    r = post(client, "/security/mfa/disable", {"password": PASSWORD, "code": code_for(secret, +1)}, page="/security")
    assert r.status_code == 303
    with SessionLocal() as db:
        user = db.scalar(select(User))
        assert not user.totp_enabled and user.totp_secret_enc is None
        assert db.scalar(select(BackupCode.id)) is None


def test_setup_not_finished_does_not_change_sign_in(client):
    signed_in(client)
    post(client, "/security/mfa/start", page="/security")  # started, never confirmed
    r = fresh_login(client)
    assert r.headers["location"] == "/dashboard"
