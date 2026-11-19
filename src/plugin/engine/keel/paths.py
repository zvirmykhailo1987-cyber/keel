# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Mykhailo Zvir

"""Де живуть дані. Vault окремо від плагіна: PLUGIN_ROOT змінюється з версією,
PLUGIN_DATA зникає при деінсталяції, а знання людини мають пережити обидва випадки."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

CONFIG_FILE = ".keel/config.json"
LAYOUT = (
    "knowledge", "growth", "overlays", "projects", "research", "inbox",
    ".keel/state/journal", ".keel/state/snapshots", ".keel/state/cards", ".keel/cache",
    ".keel/reports",
)


def home() -> Path:
    return Path(os.environ.get("KEEL_HOME") or Path.home())


def plugin_root() -> Path:
    env = os.environ.get("CLAUDE_PLUGIN_ROOT")
    return Path(env) if env else Path(__file__).resolve().parents[2]


def data_dir() -> Path:
    return plugin_root() / "data"


def _configured() -> str | None:
    try:
        return json.loads((home() / CONFIG_FILE).read_text(encoding="utf-8")).get("vault")
    except (FileNotFoundError, ValueError):
        return None


def vault_root() -> Path:
    candidate = (
        os.environ.get("KEEL_VAULT")
        or _configured()  # явний вибір у /keel:setup важливіший за значення з налаштувань плагіна
        or os.environ.get("CLAUDE_PLUGIN_OPTION_VAULT_DIR")
        or str(home() / "keel-vault")
    )
    return Path(candidate).expanduser()


@dataclass(frozen=True)
class Vault:
    root: Path

    @classmethod
    def default(cls) -> "Vault":
        return cls(vault_root())

    @property
    def keel(self) -> Path:
        return self.root / ".keel"

    @property
    def state(self) -> Path:
        return self.keel / "state"

    @property
    def journal(self) -> Path:
        return self.state / "journal"

    @property
    def snapshots(self) -> Path:
        return self.state / "snapshots"

    @property
    def cards(self) -> Path:
        return self.state / "cards"

    @property
    def cache(self) -> Path:
        return self.keel / "cache"

    @property
    def reports(self) -> Path:
        return self.keel / "reports"

    @property
    def settings_file(self) -> Path:
        return self.keel / "settings.json"

    @property
    def projects_file(self) -> Path:
        return self.state / "projects.json"

    @property
    def tick_shim(self) -> Path:
        return self.keel / "tick.py"

    @property
    def current_file(self) -> Path:
        return self.keel / "current.json"

    @property
    def exists(self) -> bool:
        return self.keel.is_dir()

    def init(self) -> None:
        for sub in LAYOUT:
            (self.root / sub).mkdir(parents=True, exist_ok=True)
