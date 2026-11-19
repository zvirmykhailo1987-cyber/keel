# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Mykhailo Zvir

"""Порівняння версій без залежностей. Незрозуміла версія дає None, а не «однакова»."""
from __future__ import annotations

import re

_NUMERIC = re.compile(r"^v?(\d+(?:\.\d+)*)")
_PRERELEASE = re.compile(r"(?i)(?:\d|[-._+])(?:a|b|rc|alpha|beta|pre|preview|dev|snapshot|canary|next|nightly|m\d)")


def parse(version: str) -> tuple[int, ...] | None:
    match = _NUMERIC.match(version.strip())
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def is_prerelease(version: str) -> bool:
    return bool(_PRERELEASE.search(version))


def gap(current: str, latest: str) -> str | None:
    """major, minor, patch, none, або None, якщо порівняти неможливо."""
    a, b = parse(current), parse(latest)
    if a is None or b is None:
        return None
    width = max(len(a), len(b), 3)
    a, b = a + (0,) * (width - len(a)), b + (0,) * (width - len(b))
    if b <= a:
        return "none"
    if b[0] != a[0]:
        return "major"
    if b[1] != a[1]:
        return "minor"
    return "patch"


def newest(versions: list[str]) -> str | None:
    stable = [v for v in versions if parse(v) is not None and not is_prerelease(v)]
    return max(stable, key=lambda v: parse(v) + (0,) * (6 - len(parse(v))), default=None)
