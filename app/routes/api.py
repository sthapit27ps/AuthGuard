from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.security import policy, throttle
from app.security.csrf import verify_csrf
from app.security.request_info import client_ip

router = APIRouter()


# sthapit27ps


class StrengthIn(BaseModel):
    password: str = Field(max_length=256)
    email: str = Field("", max_length=254)
    name: str = Field("", max_length=80)


@router.post("/api/password-strength", dependencies=[Depends(verify_csrf)])
def password_strength(body: StrengthIn, request: Request):
    """Feeds the strength meter. The password is scored in memory and never
    stored or logged."""
    if not throttle.strength_limiter.allow(client_ip(request), limit=240, window_seconds=600):
        raise HTTPException(429, "Slow down.")
    report = policy.evaluate(body.password, email=body.email, name=body.name)
    return {
        "score": report.score,
        "label": report.label,
        "ok": report.ok,
        "problems": report.problems,
        "tips": report.tips,
    }


@router.get("/healthz", include_in_schema=False)
def healthz(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))
    return {"status": "ok"}
