from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import get_settings
from app.db import init_db
from app.deps import NotAuthenticated
from app.routes import account, api, auth
from app.security import csrf, sessions
from app.templating import BASE_DIR, render

settings = get_settings()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(title="AuthGuard", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

app.include_router(auth.router)
app.include_router(account.router)
app.include_router(api.router)


# sthapit27ps

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)


@app.middleware("http")
async def hardening(request: Request, call_next):
    # Make sure every visitor has a CSRF cookie before the page is rendered.
    cookie_value = request.cookies.get(csrf.COOKIE_NAME)
    fresh = not csrf.valid_cookie_value(cookie_value)
    if fresh:
        cookie_value = csrf.new_cookie_value()
    request.state.csrf_cookie = cookie_value

    response = await call_next(request)

    if fresh:
        response.set_cookie(
            csrf.COOKIE_NAME, cookie_value, httponly=True, secure=settings.cookie_secure,
            samesite="strict", path="/",
        )
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if settings.cookie_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    if not request.url.path.startswith("/static"):
        response.headers["Cache-Control"] = "no-store"  # keep account pages out of caches
    return response


@app.exception_handler(NotAuthenticated)
async def not_authenticated(request: Request, _exc: NotAuthenticated):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": "Not signed in."}, status_code=401)
    had_cookie = sessions.COOKIE_NAME in request.cookies
    response = RedirectResponse("/login?msg=expired" if had_cookie else "/login", 303)
    if had_cookie:
        sessions.clear_cookie(response)
    return response


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    titles = {403: "Request blocked", 404: "Page not found", 405: "Not allowed", 429: "Too many requests"}
    message = exc.detail if exc.status_code != 404 else "There's nothing at this address."
    return render(
        request, "error.html", status=exc.status_code,
        title=titles.get(exc.status_code, "Something went wrong"), message=message,
    )
