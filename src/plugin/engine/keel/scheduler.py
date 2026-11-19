# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Mykhailo Zvir

"""Один інтерфейс над schtasks, launchd і cron: plan, apply, remove, verify.

Завдання викликає стабільний shim у vault, бо шлях плагіна змінюється з кожною версією.
«Зареєстровано» ще не означає «працює» (G11, G50), тому verify читає час останнього
фактичного запуску, який записує сам tick, а не лише стан планувальника."""
from __future__ import annotations

import platform
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from xml.sax.saxutils import escape

from . import clock
from .fsutil import read_json, write_text
from .paths import Vault, home

TASK_NAME = "Keel-Tick"
LAUNCHD_LABEL = "dev.keel.tick"
CRON_BEGIN = "# >>> keel tick >>>"
CRON_END = "# <<< keel tick <<<"
LAST_RUN_FILE = "tick-last.json"
STALE_HOURS = 6

Runner = Callable[..., subprocess.CompletedProcess]


def _run(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=30, **kwargs)


def background_python() -> str:
    """На Windows pythonw не відкриває консольне вікно щогодини."""
    exe = Path(sys.executable)
    if platform.system() == "Windows":
        candidate = exe.with_name("pythonw.exe")
        if candidate.exists():
            return str(candidate)
    return str(exe)


@dataclass
class Plan:
    system: str
    summary: str
    artifact: str
    target: str

    def describe(self) -> str:
        return f"Система: {self.system}\nДія: {self.summary}\nЦіль: {self.target}\n---\n{self.artifact}"


def _windows_xml(python: str, shim: Path) -> str:
    start = f"{clock.now():%Y-%m-%dT%H:00:00}"
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Keel: щогодинний tick радара (без LLM, доки фон не ввімкнено)</Description></RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition><Interval>PT1H</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>
      <StartBoundary>{start}</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Hidden>true</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec><Command>{escape(python)}</Command><Arguments>"{escape(str(shim))}"</Arguments></Exec>
  </Actions>
</Task>
"""


def _launchd_plist(python: str, shim: Path, vault: Vault) -> str:
    log = vault.reports / "tick.log"
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key><array><string>{escape(python)}</string><string>{escape(str(shim))}</string></array>
  <key>StartInterval</key><integer>3600</integer>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>{escape(str(log))}</string>
  <key>StandardErrorPath</key><string>{escape(str(log))}</string>
</dict>
</plist>
"""


def _cron_block(python: str, shim: Path) -> str:
    return f'{CRON_BEGIN}\n7 * * * * "{python}" "{shim}" >/dev/null 2>&1\n{CRON_END}\n'


def _strip_block(crontab: str) -> str:
    out, skipping = [], False
    for line in crontab.splitlines():
        if line.strip() == CRON_BEGIN:
            skipping = True
        elif line.strip() == CRON_END:
            skipping = False
        elif not skipping:
            out.append(line)
    return "\n".join(out) + ("\n" if out else "")


class Scheduler:
    def __init__(self, vault: Vault, system: str | None = None, runner: Runner = _run,
                 python: str | None = None):
        self.vault = vault
        self.system = system or platform.system()
        self.run = runner
        self.python = python or background_python()

    @property
    def plist_path(self) -> Path:
        return home() / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"

    def plan(self) -> Plan:
        shim = self.vault.tick_shim
        if self.system == "Windows":
            return Plan(self.system, f"створити завдання {TASK_NAME} (щогодини, наздоганяє після сну)",
                        _windows_xml(self.python, shim), TASK_NAME)
        if self.system == "Darwin":
            return Plan(self.system, "створити LaunchAgent (щогодини, наздоганяє після сну)",
                        _launchd_plist(self.python, shim, self.vault), str(self.plist_path))
        if self.system == "Linux":
            return Plan(self.system, "додати блок у crontab (інші рядки не змінюються)",
                        _cron_block(self.python, shim), "crontab")
        raise RuntimeError(f"Непідтримувана система: {self.system}")

    def _check(self, done: subprocess.CompletedProcess, what: str) -> None:
        if done.returncode != 0:
            raise RuntimeError(f"{what}: {done.stderr or done.stdout}".strip())

    def _crontab(self) -> str:
        done = self.run(["crontab", "-l"])
        return done.stdout if done.returncode == 0 else ""

    def apply(self) -> None:
        plan = self.plan()
        if self.system == "Windows":
            with tempfile.TemporaryDirectory() as tmp:
                xml = Path(tmp) / "task.xml"
                xml.write_text(plan.artifact, encoding="utf-16")
                self._check(self.run(["schtasks", "/Create", "/TN", TASK_NAME, "/XML", str(xml), "/F"]),
                            "schtasks /Create")
        elif self.system == "Darwin":
            write_text(self.plist_path, plan.artifact)
            self.run(["launchctl", "unload", str(self.plist_path)])
            self._check(self.run(["launchctl", "load", str(self.plist_path)]), "launchctl load")
        else:
            merged = _strip_block(self._crontab()) + plan.artifact
            self._check(self.run(["crontab", "-"], input=merged), "crontab")

    def remove(self) -> None:
        if self.system == "Windows":
            done = self.run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"])
            if done.returncode != 0 and self.registered():
                self._check(done, "schtasks /Delete")
        elif self.system == "Darwin":
            self.run(["launchctl", "unload", str(self.plist_path)])
            self.plist_path.unlink(missing_ok=True)
        else:
            self._check(self.run(["crontab", "-"], input=_strip_block(self._crontab())), "crontab")

    def registered(self) -> bool:
        if self.system == "Windows":
            return self.run(["schtasks", "/Query", "/TN", TASK_NAME]).returncode == 0
        if self.system == "Darwin":
            return self.plist_path.exists()
        return CRON_BEGIN in self._crontab()

    def verify(self) -> dict:
        """ok лише тоді, коли завдання існує І tick справді відпрацював нещодавно."""
        registered = self.registered()
        last = read_json(self.vault.state / LAST_RUN_FILE) or {}
        ran_at = last.get("ts")
        hours = None if not ran_at else clock.age_days(ran_at) * 24
        fresh = hours is not None and hours <= STALE_HOURS
        problem = None
        if not registered:
            problem = "завдання не зареєстровано"
        elif ran_at is None:
            problem = "завдання є, але tick ще жодного разу не відпрацював"
        elif not fresh:
            problem = f"останній tick {hours:.0f} год тому"
        elif last.get("error"):
            problem = f"останній tick завершився помилкою: {last['error']}"
        return {"registered": registered, "last_run": ran_at, "hours_ago": hours,
                "ok": problem is None, "problem": problem}


TICK_SHIM = '''#!/usr/bin/env python3
"""Стабільна точка входу планувальника. Створено Keel, правити не потрібно.
Шлях плагіна змінюється з версією, тому поточний читається з current.json."""
import json, os, pathlib, subprocess, sys, datetime

keel = pathlib.Path(__file__).resolve().parent
state = keel / "state" / "tick-last.json"
env = dict(os.environ, KEEL_VAULT=str(keel.parent), PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1")
error = None
try:
    root = pathlib.Path(json.loads((keel / "current.json").read_text(encoding="utf-8"))["plugin_root"])
    if not (root / "engine" / "keel").is_dir():
        raise FileNotFoundError(f"немає рушія: {root}")
    env["PYTHONPATH"] = str(root / "engine")
    env["CLAUDE_PLUGIN_ROOT"] = str(root)
    done = subprocess.run([sys.executable, "-m", "keel", "tick"], env=env, cwd=str(keel),
                          capture_output=True, timeout=3000)
    if done.returncode != 0:
        error = done.stderr.decode("utf-8", "replace")[-500:] or f"код {done.returncode}"
except Exception as exc:
    error = str(exc)
stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
state.parent.mkdir(parents=True, exist_ok=True)
state.write_text(json.dumps({"ts": stamp, "error": error}, ensure_ascii=False), encoding="utf-8")
sys.exit(1 if error else 0)
'''


def install_shim(vault: Vault) -> None:
    write_text(vault.tick_shim, TICK_SHIM)
