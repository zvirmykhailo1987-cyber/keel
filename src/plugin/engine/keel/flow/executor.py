# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Mykhailo Zvir

"""Єдине місце, де пропозиція стає дією. Модель не має іншого шляху до стану.

Правила: дія поза каталогом, неповні параметри, низька впевненість, вимкнене правило або будь-який
збій стають карткою людині. Дефолт закритий: «незрозуміло» ніколи не означає «так»."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable

from .. import clock, secretscan
from ..fsutil import read_json, write_json, write_text
from ..journal import Journal
from ..paths import Vault
from ..radar.lockfiles import Dep
from . import catalog, citeguard, depbump, gitsafe
from .calibration import blocked_domain, rule_enabled
from .cards import Card, Cards

MIN_CONFIDENCE = 0.7
MAX_FIELD = 20000
# Рушій сам іде за URL із параметрів, тож для кванта, що читав код, це канал витоку.
NETWORK_ACTIONS = {"add_fact"}
PROPOSAL_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["proposals"],
    "properties": {"proposals": {"type": "array", "maxItems": 10, "items": {
        "type": "object",
        "additionalProperties": False,
        "required": ["action", "params", "why", "confidence"],
        "properties": {
            "action": {"type": "string"},
            "params": {"type": "object"},
            "why": {"type": "string"},
            "source": {"type": "string"},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        },
    }}},
}


def _slug(text: str) -> str:
    return (re.sub(r"[^\w\-]+", "-", text.casefold()).strip("-") or "note")[:70]


def _unique(path: Path) -> Path:
    candidate, number = path, 2
    while candidate.exists():
        candidate, number = path.with_name(f"{path.stem}-{number}{path.suffix}"), number + 1
    return candidate


def _frontmatter(**fields: object) -> str:
    body = "\n".join(f"{k}: {json.dumps(v, ensure_ascii=False)}" for k, v in fields.items())
    return f"---\n{body}\n---\n\n"


class Executor:
    def __init__(self, vault: Vault):
        self.vault = vault
        self.journal = Journal(vault.journal, vault.snapshots)
        self.cards = Cards(vault)
        self.executors: dict[str, Callable[[dict], dict]] = {
            "add_note": self._add_note,
            "add_lesson": self._add_lesson,
            "add_fact": self._add_fact,
            "draft_adr": self._draft_adr,
            "update_codemap": self._update_codemap,
            "dep_patch_branch": self._dep_patch_branch,
        }
        self.actions = catalog.load(set(self.executors))

    # --- вхід ---
    def propose(self, proposal: dict, origin: str = "model", network: bool = True) -> dict:
        """Повертає {"result": executed|card|rejected|duplicate, ...}.

        network=False: пропозицію зробив квант, що читав код; мережеві дії вирішує людина."""
        name = proposal.get("action")
        params = proposal.get("params") if isinstance(proposal.get("params"), dict) else {}
        why = str(proposal.get("why", ""))[:1000]
        source = str(proposal.get("source", ""))[:500]
        confidence = proposal.get("confidence")
        leaked = self._secret_types(name, params, why, source)
        if leaked:
            # Картка не повторює значення: журнал і DECISIONS.md потрапляють у git vault.
            self.journal.append("proposal.rejected", {"why": "схоже на секрет", "types": leaked, "origin": origin})
            label = f"Пропозиція відхилена: схоже на секрет ({', '.join(leaked)}). Значення не збережено"
            return self._to_card(catalog.FALLBACK_ACTION, {"question": label}, "", "", None, origin, title=label)
        action = self.actions.get(name) if isinstance(name, str) else None
        if action is None:
            self.journal.append("proposal.rejected", {"action": str(name)[:80], "why": "дія поза каталогом", "origin": origin})
            return self._to_card(catalog.FALLBACK_ACTION, {"question": f"Пропозиція поза каталогом: {str(name)[:80]}"},
                                 why, source, confidence, origin, title=f"Невідома дія {str(name)[:60]}")
        problem = self._check_params(action, params)
        if problem:
            self.journal.append("proposal.rejected", {"action": name, "why": problem, "origin": origin})
            return {"result": "rejected", "reason": problem}
        if not network and name in NETWORK_ACTIONS:
            note = f"запит до джерела лише після схвалення людиною: {params.get('url', '')}"
            return self._to_card(name, params, why, source, confidence, origin, note=note)
        reason = self._why_not_auto(action, confidence, origin)
        if reason:
            return self._to_card(name, params, why, source, confidence, origin, note=reason)
        return self._execute(action, params, why, source, confidence, origin)

    @staticmethod
    def _secret_types(name, params: dict, why: str, source: str) -> list[str]:
        values = [str(name), why, source, *(str(v) for v in params.values())]
        return sorted({f.type for value in values for f in secretscan.scan_text(value)})

    def _why_not_auto(self, action: catalog.Action, confidence, origin: str) -> str | None:
        if not action.auto or action.tier >= 3 or action.name not in self.executors:
            return f"Tier {action.tier}: рішення людини"
        if origin == "model" and (not isinstance(confidence, (int, float)) or confidence < MIN_CONFIDENCE):
            return f"впевненість {confidence} нижча за {MIN_CONFIDENCE}"
        if not rule_enabled(self.vault, action.name):
            return "правило вимкнено через часті відкати людини"
        return None

    @staticmethod
    def _check_params(action: catalog.Action, params: dict) -> str | None:
        missing = [p for p in action.params if not str(params.get(p, "")).strip()]
        if missing:
            return f"бракує параметрів: {missing}"
        extra = set(params) - set(action.params) - set(action.optional)
        if extra:
            return f"зайві параметри: {sorted(extra)}"
        if any(len(str(v)) > MAX_FIELD for v in params.values()):
            return "завелике значення параметра"
        return None

    def _to_card(self, name: str, params: dict, why: str, source: str, confidence, origin: str,
                 note: str = "", title: str = "") -> dict:
        action = self.actions[name]
        command = ""
        if action.human:
            try:
                command = action.human.format(**params)
            except (KeyError, IndexError, ValueError):
                command = action.human
        label = title or params.get("question") or params.get("title") or params.get("claim") or \
            f"{action.desc}: " + ", ".join(str(v)[:40] for v in params.values())
        card = self.cards.create(Card(
            "", str(label)[:200], name, action.tier, params, " ".join(x for x in (why, note) if x)[:1000], source,
            confidence if isinstance(confidence, (int, float)) else None, command))
        if card is None:
            return {"result": "duplicate"}
        self.journal.append("proposal.card", {"card": card["id"], "action": name, "origin": origin})
        return {"result": "card", "card": card["id"], "reason": note}

    def _execute(self, action: catalog.Action, params: dict, why: str, source: str, confidence, origin: str) -> dict:
        try:
            outcome = self.executors[action.name](params)
        except depbump.Refused as exc:
            return self._to_card(action.name, params, why, source, confidence, origin, note=str(exc))
        except Exception as exc:  # noqa: BLE001 - збій виконання не має губитись
            self.journal.append("action.failed", {"action": action.name, "error": str(exc)[:300], "origin": origin})
            return self._to_card(action.name, params, why, source, confidence, origin, note=f"збій виконання: {exc}"[:300])
        if outcome.get("to_card"):
            return self._to_card(action.name, params, why, source, confidence, origin, note=outcome["to_card"])
        event = self.journal.append("action.executed", {
            "action": action.name, "tier": action.tier, "origin": origin, "why": why, "source": source,
            "confidence": confidence, "outcome": outcome})
        return {"result": "executed", "action": action.name, "event": event["id"], **outcome}

    # --- виконання схваленого людиною ---
    def apply_approved(self, card: dict) -> dict:
        """Tier 1-2 виконується кодом. Для Tier 3 виконавця немає: лише показ команди людині."""
        name = card["action"]
        action = self.actions.get(name)
        if action is None or name not in self.executors or action.tier >= 3:
            return {"result": "human", "command": card.get("human_command", "")}
        outcome = self._execute(action, card["params"], card.get("why", ""), card.get("source", ""),
                                card.get("confidence"), "human")
        if outcome.get("result") == "executed":
            self.cards.resolve(card["id"], "done", "system")
        return outcome

    def undo(self, event_id: str) -> dict:
        """Відкат дії Tier 1 через git revert у vault. Статистика відкатів вимикає погані правила."""
        for event in self.journal.events():
            if event["id"] == event_id and event["kind"] == "action.executed":
                commit = event["data"]["outcome"].get("commit")
                if event["data"]["outcome"].get("repo") != "vault" or not commit:
                    raise ValueError("Ця дія не відкочується автоматично: "
                                     f"{event['data']['outcome'].get('human_command') or 'видали гілку вручну'}")
                gitsafe.git_safe(["config", "user.name", "Keel"], self.vault.root)
                gitsafe.git_safe(["config", "user.email", "keel@localhost"], self.vault.root)
                gitsafe.git_safe(["revert", "--no-edit", commit], self.vault.root)
                self.journal.append("action.undone", {"event": event_id, "action": event["data"]["action"]})
                return {"result": "undone", "commit": commit}
        raise KeyError(f"Немає дії {event_id}")

    # --- виконавці ---
    def _prepare_vault(self) -> None:
        """Коміт робить `add -A` на весь vault, а його часто синхронізують на GitHub.

        Перевірка стоїть до запису: файл людини із секретом зупиняє автокоміт, а не їде в історію."""
        gitsafe.ensure_repo(self.vault.root)
        ignore = self.vault.root / ".gitignore"
        if not ignore.exists():
            write_text(ignore, ".keel/cache/\n.keel/state/\n.keel/reports/\n*.tmp\n")
        found = secretscan.scan_worktree_changes(self.vault.root)
        if found:
            places = ", ".join(f"{f.file}:{f.line} ({f.type})" for f in found[:5])
            raise RuntimeError(f"автокоміт vault зупинено, схоже на секрет: {places}")

    def _commit_vault(self, message: str) -> str | None:
        return gitsafe.commit_all(self.vault.root, message)

    def _write_note(self, folder: str, title: str, content: str, message: str) -> dict:
        self._prepare_vault()
        path = _unique(self.vault.root / folder / f"{_slug(title)}.md")
        write_text(path, content)
        return {"path": path.relative_to(self.vault.root).as_posix(),
                "commit": self._commit_vault(message), "repo": "vault"}

    def _add_note(self, p: dict) -> dict:
        body = _frontmatter(title=p["title"], created=clock.iso(), origin="keel") + p["body"].rstrip() + "\n"
        return self._write_note("knowledge", p["title"], body, f"note: {p['title'][:60]}")

    def _add_lesson(self, p: dict) -> dict:
        body = (_frontmatter(title=p["title"], created=clock.iso(), status="candidate") +
                f"{p['body'].rstrip()}\n\n**Доказ:** {p['evidence']}\n")
        return self._write_note("growth/lessons", p["title"], body, f"lesson: {p['title'][:60]}")

    def _add_fact(self, p: dict) -> dict:
        domain = citeguard.domain(p["url"])
        if blocked_domain(self.vault, domain):
            return {"to_card": f"домен {domain} заблоковано: ≥30% його цитат спростовано"}
        status, checks = citeguard.verify_fact(p["url"], p["quote"], p.get("second_url", ""),
                                               p.get("second_quote", ""), p.get("strong") in (True, "true"),
                                               self.vault.cache / "http")
        self.journal.append("fact.checked", {"status": status, "domain": domain, "url": p["url"],
                                             "reasons": [c.reason for c in checks]})
        if status != citeguard.VERIFIED:
            return {"to_card": f"факт не прийнято ({status}): " + "; ".join(c.reason for c in checks)}
        sources_md = "\n".join(f"- {c.url} (перевірено {c.checked_at})" for c in checks)
        body = (_frontmatter(claim=p["claim"], status="verified", checked=clock.iso(), domains=sorted({citeguard.domain(c.url) for c in checks})) +
                f"{p['claim']}\n\n> {p['quote']}\n\n**Джерела:**\n{sources_md}\n")
        return self._write_note("knowledge/facts", p["claim"][:60], body, f"fact: {p['claim'][:60]}")

    def _draft_adr(self, p: dict) -> dict:
        body = (_frontmatter(title=p["title"], status="draft", created=clock.iso(), project=p["project"]) +
                f"# {p['title']}\n\n## Контекст\n{p['context']}\n\n## Рішення\n{p['decision']}\n\n## Наслідки\n{p['consequences']}\n")
        return self._write_note(f"projects/{_slug(p['project'])}/adr-drafts", p["title"], body, f"adr: {p['title'][:60]}")

    def _update_codemap(self, p: dict) -> dict:
        root = self._project_root(p["project"])
        sha = gitsafe.git_safe(["rev-parse", "HEAD"], root, check=False).strip() or "немає"
        self._prepare_vault()
        path = self.vault.root / "projects" / _slug(p["project"]) / "codemap.md"
        write_text(path, _frontmatter(project=p["project"], sha=sha, updated=clock.iso()) + p["body"].rstrip() + "\n")
        return {"path": path.relative_to(self.vault.root).as_posix(),
                "commit": self._commit_vault(f"codemap: {p['project']}"), "repo": "vault", "sha": sha}

    def _project_root(self, project: str) -> Path:
        path = (read_json(self.vault.projects_file) or {}).get(project)
        if not path:
            raise ValueError(f"Невідомий проєкт: {project}")
        return Path(path)

    def _dep_patch_branch(self, p: dict) -> dict:
        root = self._project_root(p["project"])
        dep = Dep(p["ecosystem"], p["package"], p["from_version"], "")
        outcome = depbump.bump(root, dep, p["to_version"], depbump.ProjectPolicy.load(root),
                               cache_dir=self.vault.cache / "http")
        return {**outcome, "repo": "project"}


def write_settings_default(vault: Vault) -> None:
    if not vault.settings_file.exists():
        write_json(vault.settings_file, {"background": False, "quanta_per_day": 0, "quanta_per_window": 0,
                                         "watch_pages": []})
