from datetime import datetime
from pathlib import Path

from fastapi import Request
from fastapi.templating import Jinja2Templates

from app.security import policy
from app.security.csrf import form_token
from app.security.events import LABELS

BASE_DIR = Path(__file__).resolve().parent

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


# sthapit27ps

FLASH = {
    "registered": "Account created. Sign in to continue.",
    "signed_out": "You're signed out.",
    "expired": "Your session ended. Sign in again to continue.",
    "password_changed": "Password changed. Every other session was signed out.",
    "mfa_disabled": "Two-step verification is off.",
    "session_ended": "That session was ended.",
    "others_ended": "All other sessions were ended.",
}


def _stamp(value: datetime | None) -> str:
    return value.strftime("%d %b %Y, %H:%M UTC") if value else "never"


def _device(ua: str) -> str:
    if not ua:
        return "Unknown device"
    browser = next(
        (name for key, name in [("Edg/", "Edge"), ("OPR/", "Opera"), ("Firefox/", "Firefox"),
                                ("Chrome/", "Chrome"), ("Safari/", "Safari")] if key in ua),
        "Browser",
    )
    system = next(
        (name for key, name in [("iPhone", "iOS"), ("iPad", "iOS"), ("Android", "Android"),
                                ("Windows", "Windows"), ("Mac OS X", "macOS"), ("Linux", "Linux")]
         if key in ua),
        "unknown system",
    )
    return f"{browser} on {system}"


templates.env.globals["min_length"] = policy.MIN_LENGTH
templates.env.filters["stamp"] = _stamp
templates.env.filters["device"] = _device
templates.env.filters["event_label"] = lambda kind: LABELS.get(kind, kind)


def render(request: Request, name: str, status: int = 200, headers: dict | None = None, **context):
    cookie_value = getattr(request.state, "csrf_cookie", "")
    context.setdefault("csrf_token", form_token(cookie_value) if cookie_value else "")
    context.setdefault("flash", FLASH.get(request.query_params.get("msg", "")))
    context.setdefault("user", None)
    return templates.TemplateResponse(request, name, context, status_code=status, headers=headers)
