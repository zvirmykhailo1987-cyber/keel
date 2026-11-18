"""Парсери файлів залежностей. Формат, який не вдалося прочитати, повертається як
«неповний», а не як порожній: відсутність знахідок не має виглядати чистотою (G15)."""
from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "target", "build", "dist", "__pycache__",
             ".gradle", "Pods", ".next", "obj", "bin", ".keel"}
MAX_DEPTH = 5


@dataclass(frozen=True)
class Dep:
    ecosystem: str  # назва екосистеми в OSV
    name: str
    version: str
    source: str
    direct: bool | None = None  # None означає «невідомо»

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class ParseResult:
    deps: list[Dep] = field(default_factory=list)
    incomplete: list[dict] = field(default_factory=list)
    parsed_files: list[str] = field(default_factory=list)


def _clean(version: str) -> str:
    return version.strip().lstrip("v=").split("(")[0].strip()


def _npm_lock(path: Path, rel: str) -> list[Dep]:
    data = json.loads(path.read_text(encoding="utf-8"))
    deps: dict[tuple[str, str], Dep] = {}
    packages = data.get("packages")
    if packages:
        root = packages.get("", {})
        direct = {*root.get("dependencies", {}), *root.get("devDependencies", {})}
        for key, value in packages.items():
            if not key or "node_modules/" not in key or value.get("link"):
                continue
            name = value.get("name") or key.rsplit("node_modules/", 1)[1]
            if value.get("version"):
                deps[(name, value["version"])] = Dep("npm", name, value["version"], rel,
                                                     key == f"node_modules/{name}" and name in direct)
    else:
        def walk(tree: dict, top: bool) -> None:
            for name, value in tree.items():
                if value.get("version"):
                    deps[(name, value["version"])] = Dep("npm", name, value["version"], rel, top or None)
                walk(value.get("dependencies", {}), False)
        walk(data.get("dependencies", {}), True)
    return list(deps.values())


_PNPM = re.compile(r"^\s{2}'?/?(?P<name>@?[^@\s'/][^@\s']*(?:/[^@\s']+)?)[@/](?P<ver>\d[^:'()\s]*)(?:\([^:]*\))?'?:\s*(?:\{.*\})?$")


def _pnpm_lock(path: Path, rel: str) -> list[Dep]:
    deps: dict[tuple[str, str], Dep] = {}
    section = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line[0].isspace():
            section = line.rstrip(":")
        elif section in ("packages", "snapshots"):
            match = _PNPM.match(line)
            if match:
                deps.setdefault((match["name"], match["ver"]),
                                Dep("npm", match["name"], _clean(match["ver"]), rel))
    return list(deps.values())


def _yarn_lock(path: Path, rel: str) -> list[Dep]:
    deps: dict[tuple[str, str], Dep] = {}
    name = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":") and not line.startswith("#"):
            first = line.rstrip(":").split(",")[0].strip().strip('"')
            name = first.rsplit("@", 1)[0] if "@" in first[1:] else first
        elif name and re.match(r'^\s+version:?\s', line):
            version = line.split(None, 1)[1].strip().strip('"')
            deps[(name, version)] = Dep("npm", name, _clean(version), rel)
            name = None
    return list(deps.values())


def _toml_packages(ecosystem: str) -> Callable[[Path, str], list[Dep]]:
    def parse(path: Path, rel: str) -> list[Dep]:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        return [Dep(ecosystem, p["name"], str(p["version"]), rel) for p in data.get("package", [])
                if p.get("version") and p.get("name")]
    return parse


_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)(?:\[[^\]]*\])?\s*==\s*([^\s;#\\]+)")


def _requirements(path: Path, rel: str) -> list[Dep]:
    deps = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = _REQ.match(line)
        if match:
            deps.append(Dep("PyPI", match[1], match[2], rel, True))
    return deps


def _pipfile_lock(path: Path, rel: str) -> list[Dep]:
    data = json.loads(path.read_text(encoding="utf-8"))
    deps = []
    for section in ("default", "develop"):
        for name, value in data.get(section, {}).items():
            if str(value.get("version", "")).startswith("=="):
                deps.append(Dep("PyPI", name, value["version"][2:], rel))
    return deps


def _go_mod(path: Path, rel: str) -> list[Dep]:
    deps, in_block = [], False
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("//")[0].strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            line = line[len("require "):]
        elif not in_block:
            continue
        parts = line.split()
        if len(parts) >= 2:
            deps.append(Dep("Go", parts[0], parts[1], rel, "// indirect" not in raw))
    return deps


def _composer_lock(path: Path, rel: str) -> list[Dep]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [Dep("Packagist", p["name"], _clean(p["version"]), rel)
            for section in ("packages", "packages-dev") for p in data.get(section) or []]


def _gemfile_lock(path: Path, rel: str) -> list[Dep]:
    deps, in_specs = [], False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if line and not line[0].isspace():
            in_specs = False
        match = re.match(r"^ {4}([^\s(]+) \(([^)]+)\)$", line)
        if in_specs and match:
            deps.append(Dep("RubyGems", match[1], match[2].split("-")[0], rel))
    return deps


def _nuget_lock(path: Path, rel: str) -> list[Dep]:
    data = json.loads(path.read_text(encoding="utf-8"))
    deps: dict[tuple[str, str], Dep] = {}
    for framework in data.get("dependencies", {}).values():
        for name, value in framework.items():
            if value.get("resolved") and value.get("type") != "Project":
                deps[(name, value["resolved"])] = Dep("NuGet", name, value["resolved"], rel,
                                                      value.get("type") == "Direct")
    return list(deps.values())


def _gradle_lock(path: Path, rel: str) -> list[Dep]:
    deps = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#") or "=" not in line:
            continue
        coordinate = line.split("=", 1)[0].split(":")
        if len(coordinate) == 3:
            deps.append(Dep("Maven", f"{coordinate[0]}:{coordinate[1]}", coordinate[2], rel))
    return deps


def _swift_resolved(path: Path, rel: str) -> list[Dep]:
    data = json.loads(path.read_text(encoding="utf-8"))
    pins = data.get("pins") or data.get("object", {}).get("pins", [])
    deps = []
    for pin in pins:
        url = pin.get("location") or pin.get("repositoryURL")
        version = (pin.get("state") or {}).get("version")
        if url and version:
            # OSV знає пакет як github.com/owner/repo, без схеми й .git (звірено наживо).
            name = re.sub(r"^(?:https?://|git@|ssh://git@)", "", url).replace("github.com:", "github.com/")
            deps.append(Dep("SwiftURL", name.removesuffix("/").removesuffix(".git"), version, rel))
    return deps


def _pom_xml(path: Path, rel: str) -> list[Dep]:
    """Лише версії, записані прямо. Властивості й BOM не розгортаються, тому це завжди неповно."""
    root = ET.fromstring(path.read_text(encoding="utf-8"))
    ns = {"m": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}
    prefix = "m:" if ns else ""
    deps = []
    for dep in root.findall(f".//{prefix}dependency", ns):
        group = dep.findtext(f"{prefix}groupId", None, ns)
        artifact = dep.findtext(f"{prefix}artifactId", None, ns)
        version = dep.findtext(f"{prefix}version", None, ns)
        if group and artifact and version and not version.startswith("$"):
            deps.append(Dep("Maven", f"{group}:{artifact}", version.strip(), rel, True))
    return deps


PARSERS: dict[str, Callable[[Path, str], list[Dep]]] = {
    "package-lock.json": _npm_lock,
    "npm-shrinkwrap.json": _npm_lock,
    "pnpm-lock.yaml": _pnpm_lock,
    "yarn.lock": _yarn_lock,
    "poetry.lock": _toml_packages("PyPI"),
    "uv.lock": _toml_packages("PyPI"),
    "pdm.lock": _toml_packages("PyPI"),
    "requirements.txt": _requirements,
    "Pipfile.lock": _pipfile_lock,
    "Cargo.lock": _toml_packages("crates.io"),
    "go.mod": _go_mod,
    "composer.lock": _composer_lock,
    "Gemfile.lock": _gemfile_lock,
    "packages.lock.json": _nuget_lock,
    "gradle.lockfile": _gradle_lock,
    "Package.resolved": _swift_resolved,
    "pom.xml": _pom_xml,
}
# Є залежності, але точних версій без збірки ми не бачимо.
INCOMPLETE_ALWAYS = {"pom.xml": "pom.xml: властивості й BOM не розгорнуто"}
MANIFEST_WITHOUT_LOCK = {
    "package.json": ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock"),
    "pyproject.toml": ("poetry.lock", "uv.lock", "pdm.lock", "requirements.txt", "Pipfile.lock"),
    "Cargo.toml": ("Cargo.lock",),
    "composer.json": ("composer.lock",),
    "Gemfile": ("Gemfile.lock",),
    "build.gradle": ("gradle.lockfile",),
    "build.gradle.kts": ("gradle.lockfile",),
    "Package.swift": ("Package.resolved",),
    "conanfile.txt": (),
    "conanfile.py": (),
    "vcpkg.json": (),
    "CMakeLists.txt": (),
}


def iter_project_files(root: Path):
    def walk(directory: Path, depth: int):
        try:
            entries = sorted(directory.iterdir())
        except OSError:
            return
        for entry in entries:
            if entry.is_dir():
                if depth < MAX_DEPTH and entry.name not in SKIP_DIRS:
                    yield from walk(entry, depth + 1)
            else:
                yield entry
    yield from walk(Path(root), 0)


def parse_project(root: Path) -> ParseResult:
    result = ParseResult()
    seen: set[tuple[str, str, str]] = set()
    by_dir: dict[Path, set[str]] = {}
    files = list(iter_project_files(root))
    for path in files:
        by_dir.setdefault(path.parent, set()).add(path.name)
    for path in files:
        rel = path.relative_to(root).as_posix()
        name = path.name
        if name.endswith(".csproj") and "packages.lock.json" not in by_dir[path.parent]:
            result.incomplete.append({"file": rel, "reason": "немає packages.lock.json"})
        if name in MANIFEST_WITHOUT_LOCK and not (set(MANIFEST_WITHOUT_LOCK[name]) & by_dir[path.parent]):
            result.incomplete.append({"file": rel, "reason": "немає lockfile: точні версії невідомі"})
        parser = PARSERS.get(name)
        if not parser:
            continue
        try:
            parsed = parser(path, rel)
        except Exception as exc:  # noqa: BLE001 - зламаний файл не має ховатись як «0 залежностей»
            result.incomplete.append({"file": rel, "reason": f"не вдалося прочитати: {type(exc).__name__}"})
            continue
        result.parsed_files.append(rel)
        if name in INCOMPLETE_ALWAYS:
            result.incomplete.append({"file": rel, "reason": INCOMPLETE_ALWAYS[name]})
        for dep in parsed:
            key = (dep.ecosystem, dep.name, dep.version)
            if key not in seen:
                seen.add(key)
                result.deps.append(dep)
    return result
