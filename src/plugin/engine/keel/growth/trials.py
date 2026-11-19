# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Mykhailo Zvir

"""Overlay навичок із випробуванням. Оновлення плагіна затирає його файли, тому покращення
живуть у vault. Кожен overlay: гейти → коміт у vault → 14 днів випробування → revert після двох
скарг людини. Поведінкова перевірка (eval_fn) необов'язкова, бо витрачає квоту."""
from __future__ import annotations

import re
from pathlib import Path

from .. import clock, secretscan
from ..flow import gitsafe
from ..flow.citeguard import injection_signals
from ..fsutil import read_json, write_json, write_text
from ..journal import Journal
from ..paths import Vault

TRIAL_DAYS = 14
MAX_OVERLAY_CHARS = 6000
FAIL_LIMIT = 2
_NAME = re.compile(r"^[a-z][a-z0-9-]{1,40}$")


class Rejected(RuntimeError):
    pass


def _state_path(vault: Vault) -> Path:
    return vault.state / "trials.json"


def _load(vault: Vault) -> dict:
    return read_json(_state_path(vault)) or {}


def gate(text: str) -> None:
    """Гейти без LLM. Overlay йде в контекст кожної відповідної сесії, тому це вхід для ін'єкцій."""
    if len(text) > MAX_OVERLAY_CHARS:
        raise Rejected(f"overlay довший за {MAX_OVERLAY_CHARS} символів")
    if not text.strip():
        raise Rejected("порожній overlay")
    if secretscan.scan_text(text):
        raise Rejected("у тексті схоже на секрет")
    if injection_signals(text):
        raise Rejected("текст схожий на ін'єкцію інструкцій")
    if re.search(r"--dangerously-skip-permissions|bypassPermissions|--no-verify", text):
        raise Rejected("overlay не може послаблювати захист")


def propose(vault: Vault, skill: str, text: str, reason: str, eval_fn=None) -> dict:
    """Гейти йдуть до запису: зламаний overlay не потрапляє у vault узагалі."""
    if not _NAME.match(skill):
        raise Rejected(f"некоректна назва навички: {skill}")
    gate(text)
    if eval_fn is not None and not eval_fn(skill, text):
        raise Rejected("eval: нова версія не краща за стару")
    gitsafe.ensure_repo(vault.root)
    if not gitsafe.git_safe(["rev-parse", "--verify", "-q", "HEAD"], vault.root, check=False).strip():
        write_text(vault.root / ".gitignore", ".keel/cache/\n.keel/state/\n.keel/reports/\n*.tmp\n")
        gitsafe.commit_all(vault.root, "vault: старт")
    target = vault.root / "overlays" / f"{skill}.md"
    if skill in _load(vault) and _load(vault)[skill].get("status") == "trial":
        raise Rejected(f"для {skill} уже триває випробування")
    previous = target.read_text(encoding="utf-8") if target.exists() else None
    write_text(target, text.rstrip() + "\n")
    commit = gitsafe.commit_all(vault.root, f"overlay: {skill}: {reason[:60]}")
    if commit is None:
        raise Rejected("overlay не змінює нічого")
    state = _load(vault)
    state[skill] = {"status": "trial", "commit": commit, "started": clock.iso(), "reason": reason,
                    "fails": 0, "had_previous": previous is not None}
    write_json(_state_path(vault), state)
    Journal(vault.journal, vault.snapshots).append("overlay.trial", {"skill": skill, "commit": commit, "reason": reason})
    return state[skill]


def report_failure(vault: Vault, skill: str, note: str = "") -> dict:
    state = _load(vault)
    trial = state.get(skill)
    if not trial or trial["status"] != "trial":
        raise KeyError(f"Немає випробування для {skill}")
    trial["fails"] += 1
    write_json(_state_path(vault), state)
    Journal(vault.journal, vault.snapshots).append("overlay.failure", {"skill": skill, "note": note[:300]})
    return _revert(vault, skill, "скарга людини") if trial["fails"] >= FAIL_LIMIT else trial


def _revert(vault: Vault, skill: str, why: str) -> dict:
    state = _load(vault)
    trial = state[skill]
    gitsafe.git_safe(["config", "user.name", "Keel"], vault.root)
    gitsafe.git_safe(["config", "user.email", "keel@localhost"], vault.root)
    gitsafe.git_safe(["revert", "--no-edit", trial["commit"]], vault.root)
    trial.update(status="reverted", ended=clock.iso(), why=why)
    write_json(_state_path(vault), state)
    Journal(vault.journal, vault.snapshots).append("overlay.reverted", {"skill": skill, "why": why})
    return trial


def check_all(vault: Vault) -> list[dict]:
    """Випробування без скарг завершується успіхом. Ламкий каталог не зупиняє tick."""
    results = []
    state = _load(vault)
    for skill, trial in state.items():
        if trial["status"] == "trial" and clock.age_days(trial["started"]) >= TRIAL_DAYS:
            trial.update(status="graduated", ended=clock.iso())
            Journal(vault.journal, vault.snapshots).append("overlay.graduated", {"skill": skill})
            results.append({"skill": skill, "status": "graduated"})
    if results:
        write_json(_state_path(vault), state)
    return results


def active_overlays(vault: Vault) -> list[str]:
    folder = vault.root / "overlays"
    return sorted(p.stem for p in folder.glob("*.md")) if folder.is_dir() else []

