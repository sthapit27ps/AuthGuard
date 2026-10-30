from dataclasses import dataclass

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import AuthSession, User
from app.security import sessions


class NotAuthenticated(Exception):
    pass


# sthapit27ps


@dataclass
class Auth:
    user: User
    session: AuthSession


def require_auth(request: Request, db: Session = Depends(get_db)) -> Auth:
    """A fully signed-in session. A session that is still waiting for the
    authenticator code does not count."""
    row = sessions.load(db, request)
    if row is None or row.mfa_pending:
        raise NotAuthenticated()
    user = db.get(User, row.user_id)
    if user is None:
        sessions.destroy(db, row)
        raise NotAuthenticated()
    return Auth(user=user, session=row)
