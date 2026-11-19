# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Mykhailo Zvir

"""Перевірка фактів у виконавці, а не на совісті моделі.

Факт приймається, лише якщо на сторінці є дослівна цитата. Перекриття токенів
пропустило б перефразовану вигадку. Сторінка, яку не вдалося прочитати
(мережа, JS-рендер), дає UNVERIFIED, а не факт."""
from __future__ import annotations

import re
import unicodedata
import urllib.parse
from dataclasses import dataclass

from .. import clock
from ..fetch import FetchError, fetch
from ..radar.sources import page_text

VERIFIED, UNVERIFIED, REFUTED = "VERIFIED", "UNVERIFIED", "REFUTED"
MIN_QUOTE_CHARS = 20
_TRANSLATE = str.maketrans({"’": "'", "‘": "'", "ʼ": "'", "“": '"', "”": '"', "«": '"', "»": '"',
                            "–": "-", "—": "-", " ": " "})
INJECTION = [re.compile(p, re.I) for p in (
    r"ignore (?:all |any )?(?:previous|prior|above) (?:instructions|prompts?)",
    r"disregard (?:all |any )?(?:previous|prior|above)",
    r"you are now\b", r"new instructions?:", r"system prompt", r"<\s*/?\s*system\s*>",
    r"забудь (?:всі |усі )?(?:попередні|вказівки|інструкції)", r"ігноруй (?:всі |усі )?(?:попередні|вказівки|інструкції)",
    r"do not (?:tell|inform) the user", r"run (?:this|the following) (?:command|script)",
    r"curl [^\n]*\|\s*(?:ba)?sh", r"as an ai (?:assistant|model),? you must",
)]


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).translate(_TRANSLATE).casefold()
    return re.sub(r"\s+", " ", text).strip()


def injection_signals(text: str) -> list[str]:
    """Зовнішній текст це дані. Сигнал не блокує читання, а не дає тексту стати фактом автоматично."""
    return [p.pattern for p in INJECTION if p.search(text)]


def domain(url: str) -> str:
    host = urllib.parse.urlsplit(url).hostname or ""
    parts = host.lower().removeprefix("www.").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


@dataclass
class Check:
    status: str
    url: str
    reason: str
    checked_at: str
    injection: bool = False


def verify_quote(url: str, quote: str, cache_dir=None) -> Check:
    at = clock.iso()
    if len(normalize(quote)) < MIN_QUOTE_CHARS:
        return Check(UNVERIFIED, url, f"цитата коротша за {MIN_QUOTE_CHARS} символів", at)
    try:
        reply = fetch(url, cache_dir=cache_dir)
    except FetchError as exc:
        return Check(UNVERIFIED, url, f"сторінка недоступна: {exc.kind}", at)
    text = page_text(reply.text)
    if len(text) < 200:
        return Check(UNVERIFIED, url, "сторінка майже порожня: ймовірно, JS-рендер", at)
    signals = injection_signals(text)
    if normalize(quote) not in normalize(text):
        return Check(REFUTED, url, "цитати немає на сторінці", at, bool(signals))
    if injection_signals(quote):
        return Check(UNVERIFIED, url, "цитата схожа на інструкцію для моделі", at, True)
    return Check(VERIFIED, url, "дослівна цитата знайдена", at, bool(signals))


def verify_fact(url: str, quote: str, second_url: str = "", second_quote: str = "", strong: bool = False,
                cache_dir=None) -> tuple[str, list[Check]]:
    """Сильне твердження потребує двох незалежних доменів."""
    checks = [verify_quote(url, quote, cache_dir)]
    if second_url:
        checks.append(verify_quote(second_url, second_quote or quote, cache_dir))
    if any(c.status == REFUTED for c in checks):
        return REFUTED, checks
    if any(c.status != VERIFIED for c in checks):
        return UNVERIFIED, checks
    if strong and len({domain(c.url) for c in checks}) < 2:
        checks[0].reason += "; сильне твердження потребує двох незалежних доменів"
        return UNVERIFIED, checks
    return VERIFIED, checks
