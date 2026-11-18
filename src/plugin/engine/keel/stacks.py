"""Профілі стеків як дані: ознаки, команди, EOL-продукти, репозиторії для стеження."""
from __future__ import annotations

import fnmatch
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .paths import data_dir
from .radar.lockfiles import iter_project_files


@dataclass
class Stack:
    id: str
    name: str
    markers: list[str]
    commands: dict[str, str] = field(default_factory=dict)
    eol: list[str] = field(default_factory=list)
    runtime_files: dict[str, str] = field(default_factory=dict)
    frameworks: dict[str, list[str]] = field(default_factory=dict)
    watch: list[str] = field(default_factory=list)
    pitfalls: list[str] = field(default_factory=list)
    maturity: str = "profile"
    verified: str = ""


def load_stacks(directory: Path | None = None) -> list[Stack]:
    stacks = []
    for path in sorted((directory or data_dir() / "stacks").glob("*.toml")):
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
        stacks.append(Stack(id=path.stem, **raw))
    if not stacks:
        raise RuntimeError("Не знайдено жодного профілю стеку: пошкоджена установка")
    return stacks


def detect(root: Path, stacks: list[Stack] | None = None) -> list[Stack]:
    names = [p.relative_to(root).as_posix() for p in iter_project_files(root)]
    base = [n.rsplit("/", 1)[-1] for n in names]
    found = []
    for stack in stacks or load_stacks():
        if any(fnmatch.fnmatchcase(n, m) for n in base for m in stack.markers):
            found.append(stack)
    return found


def detect_frameworks(root: Path, stack: Stack, dep_names: set[str]) -> list[str]:
    return [eol for eol, packages in stack.frameworks.items() if dep_names & set(packages)]
