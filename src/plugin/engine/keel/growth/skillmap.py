# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Mykhailo Zvir

"""Карта розвитку розробника й інтервальне повторення (SM-2) без LLM.
Рівень піднімається лише доказом: ретро, ревʼю, коміт. Самооцінка без доказу не приймається."""
from __future__ import annotations

import datetime as dt

from .. import clock
from ..fsutil import read_json, write_json
from ..paths import Vault

LEVELS = ("новачок", "практик", "впевнений", "експерт")


def _path(vault: Vault):
    return vault.root / "growth" / "skills.json"


def load(vault: Vault) -> dict:
    return read_json(_path(vault)) or {"skills": {}, "cards": {}}


def save(vault: Vault, data: dict) -> None:
    write_json(_path(vault), data)


def add_evidence(vault: Vault, skill: str, evidence: str, level: int | None = None) -> dict:
    if not evidence.strip():
        raise ValueError("Рівень змінюється лише з доказом: посилання на коміт, ревʼю або ретро")
    data = load(vault)
    item = data["skills"].setdefault(skill, {"level": 0, "evidence": []})
    item["evidence"].append({"at": clock.iso(), "text": evidence[:500]})
    if level is not None:
        item["level"] = max(0, min(level, len(LEVELS) - 1))
    save(vault, data)
    return item


def add_card(vault: Vault, card_id: str, front: str, back: str) -> dict:
    data = load(vault)
    data["cards"].setdefault(card_id, {"front": front, "back": back, "ef": 2.5, "interval": 0, "reps": 0, "due": clock.iso()})
    save(vault, data)
    return data["cards"][card_id]


def sm2(card: dict, quality: int) -> dict:
    """Стандартний SM-2: quality 0..5, нижче 3 починає повторення спочатку."""
    if not 0 <= quality <= 5:
        raise ValueError("quality має бути 0..5")
    if quality < 3:
        card["reps"], card["interval"] = 0, 1
    else:
        card["reps"] += 1
        card["interval"] = 1 if card["reps"] == 1 else 6 if card["reps"] == 2 else round(card["interval"] * card["ef"])
    card["ef"] = max(1.3, card["ef"] + 0.1 - (5 - quality) * (0.08 + (5 - quality) * 0.02))
    card["due"] = clock.iso(clock.now() + dt.timedelta(days=card["interval"]))
    return card


def review(vault: Vault, card_id: str, quality: int) -> dict:
    data = load(vault)
    card = sm2(data["cards"][card_id], quality)
    save(vault, data)
    return card


def due_cards(vault: Vault) -> list[dict]:
    cards = load(vault)["cards"]
    return [{"id": k, **v} for k, v in cards.items() if clock.age_days(v["due"]) >= 0]


def next_step(vault: Vault) -> dict:
    """Один наступний крок, а не список: спершу повторення, далі найслабша навичка."""
    due = due_cards(vault)
    if due:
        return {"type": "review", "count": len(due), "card": due[0]}
    skills = load(vault)["skills"]
    if skills:
        name = min(skills, key=lambda s: (skills[s]["level"], len(skills[s]["evidence"])))
        return {"type": "practice", "skill": name, "level": LEVELS[skills[name]["level"]]}
    return {"type": "empty", "hint": "Карта порожня. Після першого /keel:retro тут з'являться навички."}
