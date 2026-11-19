# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Mykhailo Zvir

"""Картки рішень. Стан це згортка журналу, файл DECISIONS.md лише вид і канал для людини.

Денний ліміт і дедуплікація: людина, що підтверджує все пачками, не фільтрує нічого (G51)."""
from __future__ import annotations

import hashlib
import html
import re
from dataclasses import asdict, dataclass, field

from .. import clock
from ..fsutil import write_text
from ..journal import Journal
from ..paths import Vault

DAILY_LIMIT = 5
EXPIRE_DAYS = 14
JACCARD_DUPLICATE = 0.55
FOLD_VERSION = 1
_LINE = re.compile(r"^- \[(?P<mark>[ xX\-])\] `(?P<id>[0-9a-f]{6})`.*?(?:// (?P<comment>.*))?$")


@dataclass
class Card:
    id: str
    title: str
    action: str
    tier: int
    params: dict = field(default_factory=dict)
    why: str = ""
    source: str = ""
    confidence: float | None = None
    human_command: str = ""
    status: str = "open"  # open, approved, rejected, expired, done
    created: str = ""
    resolved: str = ""
    resolved_by: str = ""
    comment: str = ""
    deadline: str = ""


def _reduce(state: dict, event: dict) -> dict:
    kind, data = event["kind"], event["data"]
    if kind == "card.created":
        state[data["id"]] = data
    elif kind == "card.resolved" and data["id"] in state:
        state[data["id"]].update(status=data["status"], resolved=event["ts"], resolved_by=data.get("by", ""),
                                 comment=data.get("comment", ""))
    return state


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[\w.\-@/]{3,}", text.casefold()))


def similar(a: str, b: str) -> float:
    left, right = _tokens(a), _tokens(b)
    return len(left & right) / len(left | right) if left | right else 0.0


class Cards:
    def __init__(self, vault: Vault):
        self.vault = vault
        self.journal = Journal(vault.journal, vault.snapshots)

    def all(self) -> dict[str, dict]:
        return self.journal.fold("cards", _reduce, {}, FOLD_VERSION)

    def create(self, card: Card) -> dict | None:
        """Повертає None, якщо така картка вже відкрита або нещодавно вирішена людиною."""
        existing = self.all()
        for other in existing.values():
            same_kind = other["action"] == card.action
            if same_kind and similar(other["title"], card.title) >= JACCARD_DUPLICATE:
                if other["status"] == "open" or clock.age_days(other["created"]) < 30:
                    return None
        seed = f"{card.action}|{card.title}|{clock.iso()}"
        card.id = hashlib.sha256(seed.encode()).hexdigest()[:6]
        card.created = clock.iso()
        data = asdict(card)
        self.journal.append("card.created", data)
        return data

    def resolve(self, card_id: str, status: str, by: str, comment: str = "") -> dict:
        cards = self.all()
        if card_id not in cards:
            raise KeyError(f"Немає картки {card_id}")
        self.journal.append("card.resolved", {"id": card_id, "status": status, "by": by, "comment": comment})
        return self.all()[card_id]

    def expire_old(self) -> int:
        count = 0
        for card in self.all().values():
            if card["status"] == "open" and not card.get("deadline") and clock.age_days(card["created"]) >= EXPIRE_DAYS:
                self.resolve(card["id"], "expired", "system")
                count += 1
        return count

    def today(self) -> tuple[list[dict], list[dict]]:
        """Денні картки й запас. Дедлайн ближчий за 2 дні йде поза лімітом."""
        open_cards = [c for c in self.all().values() if c["status"] == "open"]
        def urgent(card):
            return bool(card.get("deadline")) and clock.age_days(card["deadline"]) > -2
        ordered = sorted(open_cards, key=lambda c: (not urgent(c), -(c.get("tier") or 0), c["created"]))
        pressing = [c for c in ordered if urgent(c)]
        rest = [c for c in ordered if not urgent(c)]
        slots = max(DAILY_LIMIT - len(pressing), 0)
        return pressing + rest[:slots], rest[slots:]

    def render(self) -> None:
        today, backlog = self.today()
        approved = [c for c in self.all().values() if c["status"] == "approved" and c.get("human_command")]
        lines = ["# Рішення", "", "Познач `[x]` схвалити, `[-]` відхилити, коментар після `//`. "
                 "Застосування: `/keel:decide`.", "", "## На сьогодні", ""]
        lines += [self._line(c) for c in today] or ["Рішень на сьогодні немає."]
        if approved:
            lines += ["", "## Схвалено, виконує людина", ""]
            lines += [f"- `{c['id']}` {c['title']}: `{c['human_command']}`" for c in approved]
        lines += ["", f"У запасі ще {len(backlog)}."]
        write_text(self.vault.root / "inbox" / "DECISIONS.md", "\n".join(lines) + "\n")
        write_text(self.vault.reports / "decisions.html", self._html(today, approved, len(backlog)))

    @staticmethod
    def _line(card: dict) -> str:
        extra = f" (Tier {card['tier']})"
        why = f" — {card['why']}" if card.get("why") else ""
        return f"- [ ] `{card['id']}` {card['title']}{extra}{why}"

    def apply_markdown(self) -> list[dict]:
        """Читає позначки людини. Повертає вирішені картки."""
        path = self.vault.root / "inbox" / "DECISIONS.md"
        if not path.exists():
            return []
        resolved = []
        cards = self.all()
        for raw in path.read_text(encoding="utf-8").splitlines():
            match = _LINE.match(raw)
            if not match or match["mark"] == " " or match["id"] not in cards:
                continue
            if cards[match["id"]]["status"] != "open":
                continue
            status = "rejected" if match["mark"] == "-" else "approved"
            resolved.append(self.resolve(match["id"], status, "human", (match["comment"] or "").strip()))
        return resolved

    def apply_json(self, payload: list[dict]) -> list[dict]:
        resolved = []
        cards = self.all()
        for item in payload:
            card = cards.get(str(item.get("id")))
            if card and card["status"] == "open" and item.get("status") in {"approved", "rejected"}:
                resolved.append(self.resolve(card["id"], item["status"], "human", str(item.get("comment", ""))[:500]))
        return resolved

    @staticmethod
    def _html(today: list[dict], approved: list[dict], backlog: int) -> str:
        esc = html.escape
        rows = "".join(
            f'<section class="card" data-id="{esc(c["id"])}"><h2>{esc(c["title"])}</h2>'
            f'<p class="meta">Tier {c["tier"]} · {esc(c["action"])} · {esc(c["id"])}</p>'
            f'<p>{esc(c.get("why") or "")}</p>'
            + (f'<p class="src">Джерело: {esc(c["source"])}</p>' if c.get("source") else "")
            + '<div class="row"><button data-v="approved">Схвалити</button>'
              '<button data-v="rejected">Відхилити</button>'
              '<input placeholder="Коментар" aria-label="Коментар"></div></section>'
            for c in today) or "<p>Рішень на сьогодні немає.</p>"
        done = "".join(f'<li><code>{esc(c["id"])}</code> {esc(c["title"])}<br><code>{esc(c["human_command"])}</code></li>'
                       for c in approved)
        return f"""<!doctype html><html lang="uk"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Рішення Keel</title><style>
:root{{--bg:#fff;--fg:#1c1e21;--muted:#62676d;--line:#d9dcdf;--accent:#0b5cad}}
@media (prefers-color-scheme:dark){{:root{{--bg:#16181a;--fg:#e8eaec;--muted:#9aa0a6;--line:#33373b;--accent:#6db0f5}}}}
body{{margin:0 auto;max-width:720px;padding:24px 16px;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}}
h1{{font-size:24px;margin:0 0 16px}}h2{{font-size:17px;margin:0 0 4px}}
.card{{border:1px solid var(--line);border-radius:8px;padding:16px;margin:0 0 12px}}.card.chosen{{border-color:var(--accent)}}
.meta,.src{{color:var(--muted);font-size:14px;margin:0 0 8px;overflow-wrap:anywhere}}
.row{{display:flex;gap:8px;flex-wrap:wrap}}input{{flex:1;min-width:160px;padding:8px;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:6px}}
button{{padding:8px 14px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);cursor:pointer}}
button.on,#save{{background:var(--accent);border-color:var(--accent);color:var(--bg)}}code{{overflow-wrap:anywhere}}
</style></head><body><h1>Рішення</h1>{rows}<p class="meta">У запасі ще {backlog}.</p>
{"<h2>Схвалено, виконує людина</h2><ul>"+done+"</ul>" if done else ""}
<button id="save">Зберегти рішення</button><p class="meta">Файл збережеться в Завантаження. Потім: /keel:decide</p>
<script>
const out={{}};document.querySelectorAll('.card').forEach(c=>{{c.querySelectorAll('button').forEach(b=>b.onclick=()=>{{
c.querySelectorAll('button').forEach(x=>x.classList.remove('on'));b.classList.add('on');c.classList.add('chosen');
out[c.dataset.id]={{id:c.dataset.id,status:b.dataset.v}}}});}});
document.getElementById('save').onclick=()=>{{document.querySelectorAll('.card').forEach(c=>{{if(out[c.dataset.id])out[c.dataset.id].comment=c.querySelector('input').value}});
const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(Object.values(out))],{{type:'application/json'}}));
a.download='keel-decisions.json';a.click()}};
</script></body></html>
"""
