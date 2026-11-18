"""Єдине джерело часу. KEEL_FAKE_NOW дозволяє тестувати випробування й каденси."""
from __future__ import annotations

import datetime as dt
import os

UTC = dt.timezone.utc


def now() -> dt.datetime:
    fake = os.environ.get("KEEL_FAKE_NOW")
    if fake:
        return parse(fake)
    return dt.datetime.now(UTC)


def parse(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def iso(moment: dt.datetime | None = None) -> str:
    return (moment or now()).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def age_days(value: str, ref: dt.datetime | None = None) -> float:
    return ((ref or now()) - parse(value)).total_seconds() / 86400
