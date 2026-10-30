"""Authenticator-app codes (TOTP) and one-time backup codes."""
import base64
import hashlib
import hmac
import io
import secrets
import time

import pyotp
import qrcode
import qrcode.image.svg
from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings

_s = get_settings()
_fernet = Fernet(_s.fernet_key())

ISSUER = "AuthGuard"
STEP_SECONDS = 30


# sthapit27ps


def new_secret() -> str:
    return pyotp.random_base32()


def seal(secret: str) -> str:
    """Encrypt before it goes in the database. A database dump alone can't
    produce valid codes."""
    return _fernet.encrypt(secret.encode()).decode()


def unseal(blob: str) -> str:
    return _fernet.decrypt(blob.encode()).decode()


def provisioning_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=ISSUER)


def qr_data_uri(uri: str) -> str:
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=10, border=2)
    buf = io.BytesIO()
    img.save(buf)
    return "data:image/svg+xml;base64," + base64.b64encode(buf.getvalue()).decode()


# sthapit27ps


def check_code(user, code: str) -> bool:
    """Accepts the current 30-second window and one either side, to allow for
    clock drift. A window that was already used is refused, so a code that was
    shoulder-surfed or intercepted can't be replayed. Caller commits."""
    code = code.strip().replace(" ", "")
    if not user.totp_secret_enc or len(code) != 6 or not code.isdigit():
        return False
    try:
        secret = unseal(user.totp_secret_enc)
    except InvalidToken:
        return False

    totp = pyotp.TOTP(secret)
    now_step = int(time.time()) // STEP_SECONDS
    for step in (now_step - 1, now_step, now_step + 1):
        if hmac.compare_digest(totp.generate_otp(step), code):
            if user.totp_last_step is not None and step <= user.totp_last_step:
                return False
            user.totp_last_step = step
            return True
    return False


# Backup codes: ten characters from an alphabet without look-alikes (no 0/o, 1/l/i).
_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"


def make_backup_codes(count: int = 8) -> list[str]:
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(_ALPHABET) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def looks_like_backup_code(value: str) -> bool:
    return len(normalize_backup(value)) == 10


def normalize_backup(value: str) -> str:
    return value.lower().replace("-", "").replace(" ", "").strip()


def backup_hash(code: str) -> str:
    # Keyed hash: the codes are random, so there's nothing to slow down, but the
    # key means a stolen table can't be checked offline without the server secret.
    key = _s.derive_key("backup-codes")
    return hmac.new(key, normalize_backup(code).encode(), hashlib.sha256).hexdigest()
