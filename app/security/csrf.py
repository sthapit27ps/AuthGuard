"""CSRF protection.

Two cookies-worth of defence in one place:
  1. a random value in a strict, HttpOnly cookie; the form carries an HMAC of it
     that only this server can produce, and the two must match
  2. the Origin / Sec-Fetch-Site headers, when the browser sends them, must say
     the request came from this site
"""
import hmac
import hashlib
import secrets
from urllib.parse import urlparse

from fastapi import HTTPException, Request

from app.config import get_settings

_s = get_settings()
_key = _s.derive_key("csrf")

COOKIE_NAME = "authguard_csrf"


# sthapit27ps


def new_cookie_value() -> str:
    return secrets.token_hex(24)


def valid_cookie_value(value: str | None) -> bool:
    return bool(value) and len(value) == 48 and all(c in "0123456789abcdef" for c in value)


def form_token(cookie_value: str) -> str:
    return hmac.new(_key, cookie_value.encode(), hashlib.sha256).hexdigest()


def _same_site(request: Request) -> bool:
    # Sec-Fetch-Site is set by the browser itself and page scripts can't change
    # it, so when it's there it settles the question. (Don't lean on Origin
    # alone: a strict Referrer-Policy makes browsers send "Origin: null" even on
    # honest same-site form posts.)
    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site is not None:
        return fetch_site in ("same-origin", "none")

    # Older browsers: fall back to comparing Origin with our own Host.
    origin = request.headers.get("origin")
    if origin is not None:
        return urlparse(origin).netloc == request.headers.get("host", "")
    return True


async def verify_csrf(request: Request) -> None:
    """Route dependency for every state-changing request."""
    if not _same_site(request):
        raise HTTPException(403, "Request blocked: it didn't come from this site.")

    cookie = request.cookies.get(COOKIE_NAME)
    submitted = request.headers.get("x-csrf-token")
    if not submitted:
        content_type = request.headers.get("content-type", "")
        if content_type.startswith(("application/x-www-form-urlencoded", "multipart/form-data")):
            form = await request.form()
            submitted = str(form.get("csrf_token", ""))

    if not (valid_cookie_value(cookie) and submitted and hmac.compare_digest(form_token(cookie), submitted)):
        raise HTTPException(403, "This form has expired. Go back, reload the page and try again.")
