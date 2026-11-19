# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Mykhailo Zvir

"""Фонові LLM-кванти. Вимкнені за замовчуванням, вмикає лише людина.

Модель працює лише на читання й повертає JSON за схемою. Вона не може нічого змінити:
кожна пропозиція проходить той самий виконавець, що й решта системи.

Веб і читання коду разом ніколи. Виконавець не рятує від витоку під час самого запуску: ін'єкція зі
сторінки змусила б модель прочитати файл і передати його в URL. Тому квант із вебом працює з порожньої
теки без файлових інструментів, а квант із кодом не має мережі й не може запустити її через виконавця.
ANTHROPIC_API_KEY прибирається: із ним `claude -p` списує API, а не підписку (документація)."""
from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Callable

from .. import clock
from ..fsutil import read_json, write_json
from ..journal import Journal
from ..paths import Vault, data_dir
from .executor import PROPOSAL_SCHEMA, Executor

WINDOW_HOURS = 5
READ_ONLY = "Read,Grep,Glob"
WEB_ONLY = "WebSearch,WebFetch"
MAX_REPORT_CHARS = 60000
NEVER = "Bash,PowerShell,Write,Edit,NotebookEdit,Agent,Task"
# Стартові значення не виміряно на реальному споживанні: /keel:doctor показує фактичні запуски,
# за ними квоту треба підлаштувати.
PRESETS = {"off": (0, 0), "low": (4, 2), "max": (12, 3)}
RATE_LIMIT_PAUSE_HOURS = 5
DEFAULT_MODEL = "sonnet"
AUTH_PAUSE_HOURS = 24


@dataclass(frozen=True)
class Quantum:
    name: str
    cadence_hours: int
    web: bool = False


QUANTA = {
    "triage": Quantum("triage", 24),
    "commits": Quantum("commits", 24),
    "research": Quantum("research", 72, web=True),
    "growth": Quantum("growth", 72),
}
ORDER = ("triage", "commits", "growth", "research")


def classify_error(text: str) -> str:
    low = text.lower()
    if any(s in low for s in ("usage limit", "rate limit", "rate_limit", "too many requests", "429", "limit reached")):
        return "rate_limit"
    if any(s in low for s in ("not logged in", "authentication", "please run /login", "unauthorized", "401", "invalid api key")):
        return "auth"
    if any(s in low for s in ("network", "econn", "enotfound", "timed out", "timeout", "socket", "getaddrinfo")):
        return "network"
    return "other"


def load_settings(vault: Vault) -> dict:
    return read_json(vault.settings_file) or {"background": False, "quanta_per_day": 0, "quanta_per_window": 0}


def _runs(vault: Vault) -> list[dict]:
    journal = Journal(vault.journal, vault.snapshots)
    return [e for e in journal.events() if e["kind"] == "quantum.run"]


def quota_left(vault: Vault) -> int:
    settings = load_settings(vault)
    runs = [r for r in _runs(vault) if r["data"].get("spent")]
    day = sum(1 for r in runs if clock.age_days(r["ts"]) < 1)
    window = sum(1 for r in runs if clock.age_days(r["ts"]) * 24 < WINDOW_HOURS)
    return max(0, min(settings.get("quanta_per_day", 0) - day, settings.get("quanta_per_window", 0) - window))


def due_quantum(vault: Vault) -> str | None:
    last: dict[str, str] = {}
    for run in _runs(vault):
        if run["data"].get("spent"):
            last[run["data"]["name"]] = run["ts"]
    for name in ORDER:
        stamp = last.get(name)
        if stamp is None or clock.age_days(stamp) * 24 >= QUANTA[name].cadence_hours:
            return name
    return None


def build_prompt(vault: Vault, name: str) -> str:
    rules = (data_dir() / "quanta" / "_common.md").read_text(encoding="utf-8")
    task = (data_dir() / "quanta" / f"{name}.md").read_text(encoding="utf-8")
    actions = sorted(Executor(vault).actions)
    if QUANTA[name].web:
        report = vault.reports / "radar-latest.md"
        context = {"radar_report_text": report.read_text(encoding="utf-8")[:MAX_REPORT_CHARS] if report.is_file() else "",
                   "actions": actions}
    else:
        context = {
            "vault": str(vault.root),
            "projects": read_json(vault.projects_file) or {},
            "radar_report": str(vault.reports / "radar-latest.md"),
            "actions": actions,
        }
    return f"{rules}\n\n{task}\n\nКонтекст (JSON):\n{json.dumps(context, ensure_ascii=False, indent=2)}\n"


def _command(vault: Vault, quantum: Quantum) -> list[str]:
    exe = shutil.which("claude")
    if not exe:
        raise FileNotFoundError("не знайдено claude у PATH")
    allowed = WEB_ONLY if quantum.web else READ_ONLY
    never = f"{NEVER},{READ_ONLY if quantum.web else WEB_ONLY}"
    # --strict-mcp-config: конектори людини (пошта, диск) у фоновому кванті не потрібні й були б каналом витоку.
    command = [exe, "-p", "--output-format", "json", "--permission-mode", "dontAsk", "--allowedTools", allowed,
               "--disallowedTools", never, "--json-schema", json.dumps(PROPOSAL_SCHEMA), "--max-turns", "25",
               "--strict-mcp-config", "--model", load_settings(vault).get("quantum_model", DEFAULT_MODEL)]
    if not quantum.web:
        command += ["--add-dir", str(vault.root)]
        for path in (read_json(vault.projects_file) or {}).values():
            command += ["--add-dir", path]
    return command


def _invoke(vault: Vault, quantum: Quantum, prompt: str, env: dict, runner: Callable):
    command = _command(vault, quantum)
    options = dict(input=prompt, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1500)
    if not quantum.web:
        return runner(command, cwd=vault.root, **options)
    with tempfile.TemporaryDirectory(prefix="keel-web-") as sandbox:
        return runner(command, cwd=sandbox, **options)


def run_quantum(vault: Vault, name: str, runner: Callable = subprocess.run) -> dict:
    quantum = QUANTA[name]
    journal = Journal(vault.journal, vault.snapshots)
    env = {k: v for k, v in os.environ.items() if k not in {"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"}}
    env["KEEL_IN_QUANTUM"] = "1"
    state_path = vault.state / "quanta.json"
    state = read_json(state_path) or {}
    prompt = build_prompt(vault, name)  # зламаний пакет не маскується під «немає CLI»
    try:
        done = _invoke(vault, quantum, prompt, env, runner)
    except subprocess.TimeoutExpired:
        journal.append("quantum.run", {"name": name, "spent": True, "error": "timeout"})
        return {"result": "error", "kind": "timeout"}
    except FileNotFoundError as exc:
        journal.append("quantum.run", {"name": name, "spent": False, "error": "no_cli"})
        return {"result": "error", "kind": "no_cli", "detail": str(exc)}
    payload = None
    try:
        payload = json.loads(done.stdout)
    except ValueError:
        pass
    failed = done.returncode != 0 or payload is None or payload.get("is_error")
    if failed:
        text = (done.stderr or "") + " " + ((payload or {}).get("result") or done.stdout or "")
        kind = classify_error(text)
        pause = {"rate_limit": RATE_LIMIT_PAUSE_HOURS, "auth": AUTH_PAUSE_HOURS}.get(kind)
        if pause:
            state["paused_until"] = clock.iso(clock.now() + dt.timedelta(hours=pause))
            state["pause_reason"] = kind
            write_json(state_path, state)
        journal.append("quantum.run", {"name": name, "spent": kind not in {"auth", "network"}, "error": kind})
        return {"result": "error", "kind": kind}
    output = payload.get("structured_output") or {}
    proposals = output.get("proposals") if isinstance(output, dict) else None
    if not isinstance(proposals, list):
        journal.append("quantum.run", {"name": name, "spent": True, "error": "schema"})
        return {"result": "error", "kind": "schema"}
    executor = Executor(vault)
    results = [executor.propose(p if isinstance(p, dict) else {}, origin="model", network=quantum.web)
               for p in proposals[:10]]
    journal.append("quantum.run", {"name": name, "spent": True, "proposals": len(results)})
    return {"result": "ok", "name": name, "outcomes": results}


def maybe_run(vault: Vault, runner: Callable = subprocess.run) -> dict:
    settings = load_settings(vault)
    if not settings.get("background"):
        return {"result": "off"}
    state = read_json(vault.state / "quanta.json") or {}
    paused = state.get("paused_until")
    if paused and clock.age_days(paused) < 0:
        return {"result": "paused", "until": paused, "reason": state.get("pause_reason")}
    if quota_left(vault) <= 0:
        return {"result": "quota"}
    name = due_quantum(vault)
    if name is None:
        return {"result": "nothing_due"}
    return run_quantum(vault, name, runner)


def set_preset(vault: Vault, preset: str) -> dict:
    day, window = PRESETS[preset]
    settings = load_settings(vault)
    settings.update(background=preset != "off", quanta_per_day=day, quanta_per_window=window)
    write_json(vault.settings_file, settings)
    return settings
