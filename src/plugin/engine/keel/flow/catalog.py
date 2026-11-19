# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Mykhailo Zvir

"""Каталог дій. Перевіряється при завантаженні: помилка конфігурації зупиняє рушій, а не
з'являється посеред ночі як KeyError під час дії."""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from ..paths import data_dir

KNOWN_FIELDS = {"tier", "auto", "params", "optional", "desc", "human"}
FALLBACK_ACTION = "human_decision"


class CatalogError(RuntimeError):
    pass


@dataclass(frozen=True)
class Action:
    name: str
    tier: int
    auto: bool
    params: tuple[str, ...]
    optional: tuple[str, ...] = field(default_factory=tuple)
    desc: str = ""
    human: str = ""


def validate(raw: dict, executors: set[str]) -> dict[str, Action]:
    actions: dict[str, Action] = {}
    for name, spec in raw.get("actions", {}).items():
        unknown = set(spec) - KNOWN_FIELDS
        if unknown:
            raise CatalogError(f"{name}: невідомі поля {sorted(unknown)}")
        tier = spec.get("tier")
        if tier not in (0, 1, 2, 3):
            raise CatalogError(f"{name}: tier має бути 0..3")
        auto = spec.get("auto")
        if not isinstance(auto, bool):
            raise CatalogError(f"{name}: auto має бути булевим і вказаним явно")
        if tier >= 3 and auto:
            raise CatalogError(f"{name}: Tier {tier} не може бути автоматичним")
        if tier >= 3 and name in executors:
            raise CatalogError(f"{name}: Tier {tier} не може мати виконавця")
        if auto and name not in executors:
            raise CatalogError(f"{name}: auto=true без виконавця")
        actions[name] = Action(name, tier, auto, tuple(spec.get("params", ())),
                               tuple(spec.get("optional", ())), spec.get("desc", ""), spec.get("human", ""))
    extra = executors - set(actions)
    if extra:
        raise CatalogError(f"виконавці без запису в каталозі: {sorted(extra)}")
    if FALLBACK_ACTION not in actions:
        raise CatalogError(f"у каталозі немає {FALLBACK_ACTION}")
    return actions


def load(executors: set[str], path: Path | None = None) -> dict[str, Action]:
    raw = tomllib.loads((path or data_dir() / "actions.toml").read_text(encoding="utf-8"))
    return validate(raw, executors)
