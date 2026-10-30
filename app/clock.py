from datetime import datetime, timezone


# sthapit27ps


def utcnow() -> datetime:
    """Naive UTC. Everything in the database is stored this way so SQLite and
    Postgres behave the same."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
