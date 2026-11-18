"""Навчання на рішеннях людини: чесність джерел, калібрування впевненості, вимкнення правил.
Лише згортка журналу, без LLM."""
from __future__ import annotations

from ..journal import Journal
from ..paths import Vault

RULE_MIN_SAMPLES = 8
RULE_ROLLBACK_LIMIT = 0.15
DOMAIN_MIN_SAMPLES = 5
DOMAIN_REFUTED_LIMIT = 0.30
SOURCE_MIN_SAMPLES = 20
SOURCE_WEIGHT_FLOOR = 0.15
FOLD_VERSION = 1


def _reduce(state: dict, event: dict) -> dict:
    kind, data = event["kind"], event["data"]
    if kind == "action.executed":
        rule = state["rules"].setdefault(data["action"], {"done": 0, "undone": 0})
        if data.get("origin") != "human":
            rule["done"] += 1
    elif kind == "action.undone":
        rule = state["rules"].setdefault(data["action"], {"done": 0, "undone": 0})
        rule["undone"] += 1
    elif kind == "fact.checked":
        item = state["domains"].setdefault(data["domain"], {"verified": 0, "refuted": 0})
        if data["status"] == "VERIFIED":
            item["verified"] += 1
        elif data["status"] == "REFUTED":
            item["refuted"] += 1
    elif kind == "card.created":
        state["cards"][data["id"]] = {"source": data.get("source") or "", "confidence": data.get("confidence")}
    elif kind == "card.resolved" and data.get("by") == "human" and data["id"] in state["cards"]:
        card = state["cards"].pop(data["id"])
        yes = data["status"] == "approved"
        source = card["source"].split("/")[2] if "://" in card["source"] else card["source"][:40]
        if source:
            item = state["sources"].setdefault(source, {"yes": 0, "no": 0})
            item["yes" if yes else "no"] += 1
        if isinstance(card["confidence"], (int, float)):
            state["brier_sum"] += (card["confidence"] - (1.0 if yes else 0.0)) ** 2
            state["brier_n"] += 1
    return state


def stats(vault: Vault) -> dict:
    initial = {"rules": {}, "domains": {}, "sources": {}, "cards": {}, "brier_sum": 0.0, "brier_n": 0}
    return Journal(vault.journal, vault.snapshots).fold("calibration", _reduce, initial, FOLD_VERSION)


def rule_enabled(vault: Vault, action: str) -> bool:
    rule = stats(vault)["rules"].get(action)
    if not rule or rule["done"] < RULE_MIN_SAMPLES:
        return True
    return rule["undone"] / rule["done"] < RULE_ROLLBACK_LIMIT


def blocked_domain(vault: Vault, domain: str) -> bool:
    item = stats(vault)["domains"].get(domain)
    if not item:
        return False
    total = item["verified"] + item["refuted"]
    return total >= DOMAIN_MIN_SAMPLES and item["refuted"] / total >= DOMAIN_REFUTED_LIMIT


def source_weight(yes: int, no: int) -> float:
    """Згладжування Лапласа: одне «так» не робить джерело ідеальним."""
    return (yes + 1) / (yes + no + 2)


def weak_sources(vault: Vault) -> list[str]:
    return [name for name, item in stats(vault)["sources"].items()
            if item["yes"] + item["no"] >= SOURCE_MIN_SAMPLES
            and source_weight(item["yes"], item["no"]) < SOURCE_WEIGHT_FLOOR]


def brier(vault: Vault) -> float | None:
    data = stats(vault)
    return data["brier_sum"] / data["brier_n"] if data["brier_n"] else None
