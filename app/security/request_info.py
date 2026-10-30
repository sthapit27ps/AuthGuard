from fastapi import Request

from app.config import get_settings

_s = get_settings()


# sthapit27ps


def client_ip(request: Request) -> str:
    """The address we rate-limit on. Only believe X-Forwarded-For when the app
    really sits behind one reverse proxy (TRUST_PROXY_HEADERS=true); the last
    entry is the one that proxy added, earlier ones can be forged by the client."""
    if _s.trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[-1].strip()[:64]
    return (request.client.host if request.client else "unknown")[:64]


def user_agent(request: Request) -> str:
    return request.headers.get("user-agent", "")[:200]
