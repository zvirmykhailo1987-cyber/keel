"""Щогодинний цикл. Ідемпотентний: строки обчислює зі стану, тож переживає сон ноутбука."""
from __future__ import annotations

from .flow import pipeline, quanta
from .flow.calibration import weak_sources
from .flow.cards import Cards
from .flow.executor import Executor, write_settings_default
from .fsutil import FileLock, LockBusy, read_json
from .journal import Journal
from .paths import Vault
from .radar import engine as radar


def apply_decisions(vault: Vault, executor: Executor, payload: list[dict] | None = None) -> list[dict]:
    """Застосовує позначки людини. Tier 3 тут лише отримує статус: виконує людина."""
    cards = Cards(vault)
    resolved = cards.apply_json(payload) if payload is not None else cards.apply_markdown()
    outcomes = []
    for card in resolved:
        item = {"id": card["id"], "status": card["status"], "title": card["title"]}
        if card["status"] == "approved":
            item["outcome"] = executor.apply_approved(card)
        outcomes.append(item)
    return outcomes


def run(vault: Vault, force_radar: bool = False, quantum_runner=None) -> dict:
    vault.init()
    write_settings_default(vault)
    try:
        with FileLock(vault.state / "tick.lock", stale_seconds=3000, wait_seconds=1):
            executor = Executor(vault)
            decisions = apply_decisions(vault, executor)
            scan = radar.run(vault, force=force_radar)
            actions = pipeline.process(vault, scan["new"], executor)
            state = read_json(vault.state / "radar.json") or {}
            actions += pipeline.silent_sources(vault, state.get("source_errors", {}), executor)
            for source in weak_sources(vault):
                actions.append(executor.propose({
                    "action": "human_decision", "source": source,
                    "why": "Людина відхиляє майже все з цього джерела.",
                    "params": {"question": f"Перестати брати пропозиції з {source}?"}}, origin="system"))
            cards = Cards(vault)
            expired = cards.expire_old()
            from .growth import trials  # noqa: PLC0415 - необов'язковий шар вище за flow
            trial_results = trials.check_all(vault)
            background = quanta.maybe_run(vault, quantum_runner) if quantum_runner else quanta.maybe_run(vault)
            cards.render()
            summary = {"decisions": len(decisions), "new_findings": len(scan["new"]), "total_findings": scan["total"],
                       "actions": len(actions), "expired": expired, "unchecked": len(scan["unchecked"]),
                       "source_errors": len(scan["errors"]), "trials": trial_results, "background": background.get("result")}
            Journal(vault.journal, vault.snapshots).append("tick", summary)
            return summary
    except LockBusy:
        return {"result": "busy"}
