"""Діагностика. Кожна перевірка міряє факт: запускає, а не читає файл настройок (G11, G16).
Звіт не містить коду й секретів, тому ним можна поділитись для виправлення."""
from __future__ import annotations

import os
import platform
import shutil
import ssl
import subprocess
import sys
from pathlib import Path

from . import __version__, secretscan
from .flow import catalog, quanta
from .flow.executor import Executor
from .fsutil import read_json
from .journal import Journal
from .paths import Vault, plugin_root
from .scheduler import Scheduler

OK, WARN, FAIL = "ok", "warn", "fail"


def _item(name: str, status: str, detail: str = "", fix: str = "") -> dict:
    return {"name": name, "status": status, "detail": detail, "fix": fix}


def _version(args: list[str]) -> str | None:
    try:
        done = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20)
        return (done.stdout or done.stderr).strip().splitlines()[0] if done.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired, IndexError):
        return None


def check_tools() -> list[dict]:
    items = [_item("python", OK if sys.version_info >= (3, 11) else FAIL, platform.python_version(),
                   "Потрібен Python 3.11+")]
    git = _version(["git", "--version"])
    items.append(_item("git", OK if git else FAIL, git or "не знайдено", "Встанови git"))
    claude = shutil.which("claude")
    items.append(_item("claude у PATH", OK if claude else WARN, claude or "не знайдено",
                       "Без нього фонові кванти не запустяться. Radar працює і так."))
    sh = shutil.which("sh")
    items.append(_item("sh", OK if sh else FAIL, sh or "не знайдено",
                       "Без sh хуки Keel не спрацюють. На Windows встанови Git for Windows."))
    gitleaks = shutil.which("gitleaks")
    items.append(_item("gitleaks", OK, gitleaks or "не знайдено: локально працює лише вбудований сканер",
                       "Локальні гейти це страховка. Жорстка межа на сервері: GitHub push protection або gitleaks у CI."))
    return items


def check_billing() -> list[dict]:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return [_item("ANTHROPIC_API_KEY", WARN, "задано в середовищі",
                      "Інтерактивний `claude -p` із цим ключем списує API, а не підписку. "
                      "Фонові кванти Keel ключ прибирають, але перевір свої скрипти.")]
    return [_item("ANTHROPIC_API_KEY", OK, "не задано")]


def check_tls() -> list[dict]:
    context = ssl.create_default_context()
    count = len(context.get_ca_certs())
    if count:
        return [_item("сертифікати TLS", OK, f"{count} кореневих")]
    return [_item("сертифікати TLS", WARN, "сховище порожнє або завантажується відкладено",
                  "На macOS із python.org запусти `Install Certificates.command`. Перевірку TLS Keel не вимикає ніколи.")]


def check_engine(vault: Vault) -> list[dict]:
    items = []
    try:
        Executor(vault)
        items.append(_item("каталог дій", OK))
    except catalog.CatalogError as exc:
        items.append(_item("каталог дій", FAIL, str(exc)))
    probe = "x = " + repr("ghp_" + "a1B2c3D4" * 5)
    items.append(_item("сканер секретів бачить токен", OK if secretscan.scan_text(probe) else FAIL))
    return items


def check_vault(vault: Vault) -> list[dict]:
    if not vault.exists:
        return [_item("vault", FAIL, str(vault.root), "Запусти /keel:setup")]
    items = [_item("vault", OK, str(vault.root))]
    current = read_json(vault.current_file) or {}
    root = Path(current.get("plugin_root", ""))
    items.append(_item("current.json", OK if (root / "engine" / "keel").is_dir() else WARN, current.get("version", "немає"),
                       "Запусти нову сесію Claude Code: хук оновить шлях."))
    try:
        count = sum(1 for _ in Journal(vault.journal, vault.snapshots).events())
        items.append(_item("журнал", OK, f"{count} подій"))
    except Exception as exc:  # noqa: BLE001
        items.append(_item("журнал", FAIL, str(exc)))
    projects = read_json(vault.projects_file) or {}
    gone = [name for name, path in projects.items() if not Path(path).is_dir()]
    items.append(_item("проєкти", WARN if gone or not projects else OK,
                       f"підключено {len(projects)}" + (f", зникли: {gone}" if gone else ""), "/keel:init-project"))
    # Хук міряємо там, звідки його запустить git: core.hooksPath, заданий пізніше, тихо вимикає .git/hooks.
    from .project import hook_status  # noqa: PLC0415 - легкий імпорт лише для лікаря
    missing = {name: [h for h, ok in hook_status(Path(path)).items() if not ok]
               for name, path in projects.items() if Path(path).is_dir()}
    missing = {name: hooks for name, hooks in missing.items() if "reference-transaction" in hooks}
    items.append(_item("git-хуки проєктів", WARN if missing else OK,
                       f"без reference-transaction: {sorted(missing)}" if missing else "reference-transaction діє",
                       "/keel:init-project у цьому репозиторії; перевір core.hooksPath"))
    return items


def check_schedule(vault: Vault) -> list[dict]:
    settings = read_json(vault.settings_file) or {}
    if not settings.get("schedule_enabled"):
        return [_item("планувальник", WARN, "вимкнено: Radar працює лише вручну", "/keel:autopilot schedule")]
    health = Scheduler(vault).verify()
    return [_item("планувальник", OK if health["ok"] else FAIL,
                  health["problem"] or f"останній tick {health['hours_ago']:.1f} год тому", "/keel:autopilot schedule")]


def check_background(vault: Vault) -> list[dict]:
    settings = quanta.load_settings(vault)
    if not settings.get("background"):
        return [_item("фонові кванти", OK, "вимкнено (за замовчуванням)")]
    state = read_json(vault.state / "quanta.json") or {}
    runs = [e for e in Journal(vault.journal, vault.snapshots).events() if e["kind"] == "quantum.run"][-20:]
    errors = [r["data"].get("error") for r in runs if r["data"].get("error")]
    detail = f"останні {len(runs)} запусків, помилок {len(errors)}; лишилось квоти {quanta.quota_left(vault)}"
    if state.get("paused_until"):
        detail += f"; пауза до {state['paused_until']} ({state.get('pause_reason')})"
    return [_item("фонові кванти", WARN if errors else OK, detail)]


def run(vault: Vault | None = None) -> dict:
    vault = vault or Vault.default()
    items = check_tools() + check_billing() + check_tls()
    try:
        items += check_vault(vault)
        if vault.exists:
            items += check_engine(vault) + check_schedule(vault) + check_background(vault)
    except Exception as exc:  # noqa: BLE001 - лікар не має падати сам
        items.append(_item("doctor", FAIL, f"{type(exc).__name__}: {exc}"))
    worst = FAIL if any(i["status"] == FAIL for i in items) else WARN if any(i["status"] == WARN for i in items) else OK
    return {"status": worst, "version": __version__, "system": platform.platform(), "plugin_root": str(plugin_root()),
            "items": items}
