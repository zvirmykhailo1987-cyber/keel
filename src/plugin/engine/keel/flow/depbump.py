# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Mykhailo Zvir

"""Патч-оновлення залежності в окремій гілці. Без злиття і, за замовчуванням, без запуску тестів:
тести після оновлення виконують чужий код, тому це окремий дозвіл людини в project.toml."""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .. import clock
from ..fetch import FetchError, fetch
from ..radar import sources, versions
from ..radar.lockfiles import Dep
from . import gitsafe

COOLDOWN_DAYS = 7
# Команди не виконують скрипти встановлення пакетів і не запускають код проєкту.
UPDATERS: dict[str, tuple[str, list[str]]] = {
    "npm": ("package-lock.json", ["npm", "install", "{package}@{version}", "--package-lock-only", "--ignore-scripts", "--save-exact=false"]),
    "crates.io": ("Cargo.lock", ["cargo", "update", "-p", "{package}", "--precise", "{version}"]),
    "Go": ("go.mod", ["go", "get", "{package}@{version}"]),
}


class Refused(RuntimeError):
    """Передумова не виконана: дія стає карткою для людини, а не тихим пропуском."""


def release_age_days(dep: Dep, version: str, cache_dir=None) -> float | None:
    """None означає «невідомо», і карантин тоді не вважається пройденим."""
    try:
        if dep.ecosystem == "npm":
            stamp = fetch(f"https://registry.npmjs.org/{dep.name.replace('/', '%2F')}", cache_dir=cache_dir).json()["time"][version]
        elif dep.ecosystem == "PyPI":
            stamp = fetch(f"https://pypi.org/pypi/{dep.name}/{version}/json", cache_dir=cache_dir).json()["urls"][0]["upload_time_iso_8601"]
        elif dep.ecosystem == "crates.io":
            stamp = fetch(f"https://crates.io/api/v1/crates/{dep.name}/{version}", cache_dir=cache_dir).json()["version"]["created_at"]
        elif dep.ecosystem == "Go":
            escaped = re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), dep.name)
            stamp = fetch(f"https://proxy.golang.org/{escaped}/@v/{version}.info", cache_dir=cache_dir).json()["Time"]
        else:
            return None
    except (FetchError, KeyError, ValueError, IndexError):
        return None
    return clock.age_days(stamp.replace("Z", "+00:00") if isinstance(stamp, str) else stamp)


@dataclass
class ProjectPolicy:
    enabled: bool = False
    run_tests: bool = False
    test_command: str = ""
    allow: tuple[str, ...] = ()

    @classmethod
    def load(cls, root: Path) -> "ProjectPolicy":
        path = root / ".keel" / "project.toml"
        if not path.is_file():
            return cls()
        raw = tomllib.loads(path.read_text(encoding="utf-8")).get("autopilot", {})
        return cls(bool(raw.get("enabled", False)), bool(raw.get("run_tests", False)),
                   str(raw.get("test_command", "")), tuple(raw.get("allow", ())))


def preflight(dep: Dep, target: str, cache_dir=None) -> None:
    """Усі передумови. Будь-яка невідомість трактується як «ні»."""
    if dep.ecosystem not in UPDATERS:
        raise Refused(f"для {dep.ecosystem} автооновлення не реалізовано")
    if versions.gap(dep.version, target) != "patch":
        raise Refused(f"{dep.version} → {target}: це не патч-оновлення")
    if versions.is_prerelease(target):
        raise Refused(f"{target}: передрелізна версія")
    age = release_age_days(dep, target, cache_dir)
    if age is None:
        raise Refused(f"вік релізу {target} невідомий, карантин не підтверджено")
    if age < COOLDOWN_DAYS:
        raise Refused(f"реліз {target} молодший за {COOLDOWN_DAYS} днів: чекаємо (ризик supply-chain)")
    clean = sources.osv_query([Dep(dep.ecosystem, dep.name, target, dep.source)], cache_dir)
    if any(clean.values()):
        raise Refused(f"{target} має відомі вразливості за OSV")


def bump(root: Path, dep: Dep, target: str, policy: ProjectPolicy, runner=subprocess.run,
         cache_dir=None) -> dict:
    """Створює гілку keel/dep-*. Основна робоча тека й поточна гілка не змінюються."""
    if not policy.enabled:
        raise Refused("автопілот для цього проєкту вимкнено (.keel/project.toml)")
    if policy.allow and dep.name not in policy.allow:
        raise Refused(f"{dep.name} поза списком autopilot.allow у .keel/project.toml")
    preflight(dep, target, cache_dir)
    safe_name = re.sub(r"[^\w.\-]+", "-", dep.name).strip("-")
    branch = f"keel/dep-{safe_name}-{target}"
    gitsafe.assert_branch_allowed(branch)
    if gitsafe.git_safe(["branch", "--list", branch], root).strip():
        raise Refused(f"гілка {branch} уже існує")
    _lock, template = UPDATERS[dep.ecosystem]
    tool = shutil.which(template[0])
    if not tool:
        raise Refused(f"не знайдено інструмент {template[0]}")
    command = [tool] + [a.format(package=dep.name, version=target) for a in template[1:]]
    with tempfile.TemporaryDirectory(prefix="keel-wt-") as tmp:
        worktree = Path(tmp) / "wt"
        gitsafe.git_safe(["worktree", "add", "-q", "-b", branch, str(worktree), "HEAD"], root)
        try:
            done = runner(command, cwd=worktree, capture_output=True, timeout=600)
            if done.returncode != 0:
                tail = (done.stderr or b"").decode("utf-8", "replace").strip()[-300:]
                raise Refused(f"оновлення не вдалось: код {done.returncode}. {tail}")
            sha = gitsafe.commit_all(worktree, f"deps: {dep.name} {dep.version} → {target}\n\nСтворено Keel (Tier 2). Не злито.")
            if not sha:
                raise Refused("оновлення не змінило жодного файлу")
            tests = "не запускались: потрібен autopilot.run_tests у project.toml"
            if policy.run_tests and policy.test_command:
                result = runner(policy.test_command, cwd=worktree, shell=True, capture_output=True, timeout=1800)
                tests = "пройшли" if result.returncode == 0 else f"впали, код {result.returncode}"
        except Exception:
            gitsafe.discard_keel_branch(root, branch, worktree)
            raise
        gitsafe.git_safe(["worktree", "remove", str(worktree)], root, check=False)
    gitsafe.git_safe(["worktree", "prune"], root, check=False)
    return {"branch": branch, "commit": sha, "tests": tests,
            "human_command": f"git diff HEAD...{branch}  # потім: git merge --no-ff {branch}"}
