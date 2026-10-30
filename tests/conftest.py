import html
import os
import re
import tempfile

# Settings are read when the app is imported, so these go first.
_tmp = tempfile.mkdtemp()
os.environ.update(
    {
        "AUTHGUARD_ENV": "dev",
        "SECRET_KEY": "test-secret-key-that-is-long-enough-for-hkdf-0123456789",
        "DATABASE_URL": f"sqlite:///{_tmp}/test.db",
        "COOKIE_SECURE": "true",
        # cheap hashing so the suite is fast; production defaults are in config.py
        "ARGON2_TIME_COST": "1",
        "ARGON2_MEMORY_KIB": "1024",
        "ARGON2_PARALLELISM": "1",
    }
)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

# sthapit27ps

PASSWORD = "violet-lantern-orbit-quiet-9"
OTHER_PASSWORD = "harbor-maple-tundra-river-42"


@pytest.fixture(autouse=True)
def fresh_db():
    from app.db import Base, engine, init_db

    init_db()
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield


@pytest.fixture
def client():
    from app.main import app

    # https base URL so the Secure cookies are actually sent back
    with TestClient(app, base_url="https://testserver") as c:
        yield c


@pytest.fixture
def make_client():
    from app.main import app

    opened = []

    def _make():
        c = TestClient(app, base_url="https://testserver")
        c.__enter__()
        opened.append(c)
        return c

    yield _make
    for c in opened:
        c.__exit__(None, None, None)


def body(response):
    """Response text with HTML entities decoded (so \"don't\" matches)."""
    return html.unescape(response.text)


def csrf_token(client, page="/login"):
    html = client.get(page).text
    return re.search(r'name="csrf" content="([0-9a-f]+)"', html).group(1)


def post(client, path, data=None, page=None):
    """POST a form the way a browser would: fetch a page, copy its CSRF token."""
    body = dict(data or {})
    body["csrf_token"] = csrf_token(client, page or path)
    return client.post(path, data=body, follow_redirects=False)


def register(client, email="sam@example.com", password=PASSWORD, name="Sam"):
    return post(client, "/register", {
        "email": email, "display_name": name, "password": password, "confirm": password,
    })


def login(client, email="sam@example.com", password=PASSWORD):
    return post(client, "/login", {"email": email, "password": password})


def signed_in(client, **kw):
    register(client, **kw)
    r = login(client, **{k: v for k, v in kw.items() if k in ("email", "password")})
    assert r.status_code == 303 and r.headers["location"] == "/dashboard"
    return client
