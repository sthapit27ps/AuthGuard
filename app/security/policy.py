"""Password rules: length, common passwords, personal info, strength score."""
import re
from dataclasses import dataclass, field

from zxcvbn import zxcvbn

from app.config import get_settings

_s = get_settings()

MIN_LENGTH = _s.min_password_length
MAX_LENGTH = 128
MIN_SCORE = 3  # zxcvbn: 0 (terrible) .. 4 (very hard to guess)
LABELS = ["Very weak", "Weak", "Fair", "Good", "Strong"]


# sthapit27ps


@dataclass
class PasswordReport:
    ok: bool
    score: int
    label: str
    problems: list[str] = field(default_factory=list)
    tips: list[str] = field(default_factory=list)


def _looks_common(result: dict, password: str) -> bool:
    """True when most of the password is made of entries from the common-password list."""
    covered = 0
    for m in result["sequence"]:
        if (
            m.get("pattern") == "dictionary"
            and m.get("dictionary_name") == "passwords"
            and m.get("rank", 10**9) <= 10_000
        ):
            covered += len(m["token"])
    return covered >= 0.8 * len(password)


def _personal_bits(email: str, name: str) -> list[str]:
    bits = []
    local = email.split("@")[0].lower()
    if local:
        bits.append(local)
    bits += [p.lower() for p in re.split(r"\W+", name) if p]
    return [b for b in bits if len(b) >= 4]


def evaluate(password: str, *, email: str = "", name: str = "") -> PasswordReport:
    n = len(password)
    if n == 0:
        return PasswordReport(ok=False, score=0, label="", problems=["Enter a password."])

    problems: list[str] = []
    if n < MIN_LENGTH:
        problems.append(f"Use at least {MIN_LENGTH} characters. This one has {n}.")
    if n > MAX_LENGTH:
        problems.append(f"Keep it to {MAX_LENGTH} characters or fewer.")

    personal = _personal_bits(email, name)
    # zxcvbn is slow on very long input, and 72 characters is plenty to judge
    result = zxcvbn(password[:72], user_inputs=personal)
    score = result["score"]

    lowered = password.lower()
    if any(bit in lowered for bit in personal):
        problems.append("Leave your name and email out of it.")

    if _looks_common(result, password):
        problems.append("That's one of the most common passwords. Pick something less guessable.")
    elif score < MIN_SCORE and n >= MIN_LENGTH:
        warning = result["feedback"].get("warning") or "That's too easy to guess."
        problems.append(warning.rstrip(".") + ".")

    tips = [t.rstrip(".") + "." for t in result["feedback"].get("suggestions", [])]
    if score < MIN_SCORE and not tips:
        tips = ["Try four or five unrelated words strung together."]

    return PasswordReport(
        ok=not problems,
        score=score,
        label=LABELS[score],
        problems=problems,
        tips=tips if score < MIN_SCORE else [],
    )
