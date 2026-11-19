#!/usr/bin/env python3
"""Збирає дистрибутив Keel: dist/keel-marketplace/ і ZIP із тих самих файлів.

Нічого не публікує. Будь-який збій зупиняє збірку й видаляє результат.
Denylist особистих маркерів лежить поза репо: без нього збірка відмовляється працювати,
бо «перевірити ні з чим» інакше виглядало б як «чисто» (Г22).
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "plugin"
DIST = ROOT / "dist" / "keel-marketplace"
ZIP_PATH = ROOT / "dist" / "keel-marketplace.zip"
REPORT = ROOT / "dist" / "BUILD-REPORT.md"
# Denylist is private by design (it lists the very terms that must never ship), so it lives outside git.
DEFAULT_DENYLIST = Path(os.environ.get("KEEL_DENYLIST") or ROOT / "build" / "denylist.local.txt")
PLACEHOLDER = re.compile(r"\{\{[A-Z_]+\}\}")
TEXT_SUFFIXES = {".py", ".md", ".json", ".toml", ".sh", ".txt", ".yml", ".yaml", ".lock", ".mod", ".sum",
                 ".xml", ".gradle", ".csproj", ".kts", ""}
FORBIDDEN_PARTS = {"__pycache__", ".eval-cache", ".git", ".tmp", "_private"}
ZIP_EPOCH = (2026, 1, 1, 0, 0, 0)
# Перевірка на трьох ОС, включно з macOS, якої локально немає. Версії закріплено за SHA.
CI_WORKFLOW = """name: selftest
on: [push, pull_request]
permissions:
  contents: read
jobs:
  selftest:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        python: ["3.11", "3.13"]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8  # v5.0.0
      - uses: actions/setup-python@e797f83bcb11b83ae66e0230d6156d7c80228e7c  # v6.0.0
        with:
          python-version: ${{ matrix.python }}
      - name: Тести рушія
        shell: bash
        run: sh plugins/keel/hooks/run.sh -m keel selftest
"""
sys.path.insert(0, str(SRC / "engine"))


class BuildError(RuntimeError):
    pass


def _matches(rel: str, pattern: str) -> bool:
    if "**" in pattern:
        prefix = pattern.split("**")[0]
        return rel.startswith(prefix) and not rel.endswith("/")
    return fnmatch.fnmatchcase(rel, pattern) and rel.count("/") == pattern.count("/")


def select_files(src: Path, patterns: list[str]) -> tuple[list[str], list[str]]:
    all_files = sorted(p.relative_to(src).as_posix() for p in src.rglob("*") if p.is_file())
    chosen = [f for f in all_files if any(_matches(f, p) for p in patterns)]
    return chosen, sorted(set(all_files) - set(chosen))


def load_denylist(path: Path) -> list[str]:
    if not path.is_file():
        raise BuildError(f"немає denylist: {path}. Без нього перевірка особистих даних неможлива.")
    terms = [t.strip() for t in path.read_text(encoding="utf-8").splitlines()
             if t.strip() and not t.startswith("#")]
    if len(terms) < 5:
        raise BuildError(f"denylist підозріло короткий ({len(terms)}): перевір файл.")
    return terms


def check_denylist(tree: Path, terms: list[str], public: list[str] = ()) -> list[str]:
    """Перевіряє і вміст, і імена файлів. У звіт іде номер терміна, а не значення:
    звіт теж можуть переслати.

    `public` це свідомо публічна ідентичність автора (ім'я, адреса репозиторію). Маскуються лише
    ці точні рядки: той самий термін в іншому контексті, наприклад у поштовій адресі, лишається знахідкою."""
    masks = sorted((p.lower() for p in public if p), key=len, reverse=True)
    # Межа зліва: корінь імені не має спрацьовувати всередині звичайного слова.
    patterns = [(i, re.compile(r"(?<![\w])" + re.escape(t.lower()))) for i, t in enumerate(terms)]
    hits: list[str] = []
    for path in sorted(tree.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(tree).as_posix()
        haystacks = [rel.lower()]
        haystacks.append(path.read_bytes().decode("utf-8", errors="ignore").lower())
        for mask in masks:
            haystacks = [text.replace(mask, " " * len(mask)) for text in haystacks]
        for index, pattern in patterns:
            if any(pattern.search(text) for text in haystacks):
                hits.append(f"{rel}: термін №{index}")
    return hits


def check_text_rules(tree: Path) -> list[str]:
    errors: list[str] = []
    for path in sorted(tree.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(tree).as_posix()
        if set(Path(rel).parts) & FORBIDDEN_PARTS:
            errors.append(f"{rel}: заборонена тека")
        if path.suffix.lower() in TEXT_SUFFIXES:
            data = path.read_bytes()
            if b"\r\n" in data:
                errors.append(f"{rel}: CRLF (агент із CRLF стає невидимим, Г42)")
            if PLACEHOLDER.search(data.decode("utf-8", errors="ignore")):
                errors.append(f"{rel}: незаповнена підстановка")
    return errors


def apply_params(text: str, params: dict[str, str]) -> str:
    for key, value in params.items():
        text = text.replace("{{" + key + "}}", value)
    return text


def manifest_description(src: Path) -> str:
    return json.loads((src / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))["description"]


def public_identity(params: dict) -> list[str]:
    return [str(v) for v in params.get("PUBLIC_IDENTITY", [])]


def write_marketplace(dist: Path, params: dict[str, str], version: str) -> None:
    meta = dist / ".claude-plugin"
    meta.mkdir(parents=True)
    (meta / "marketplace.json").write_text(json.dumps({
        "name": params["MARKETPLACE_NAME"],
        "owner": {"name": params["OWNER_NAME"]},
        "plugins": [{"name": params["PLUGIN_NAME"], "source": f"./plugins/{params['PLUGIN_NAME']}",
                     "version": version,
                     "description": manifest_description(SRC)}],
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    (dist / ".gitattributes").write_text("* text=auto eol=lf\n", encoding="utf-8", newline="\n")
    (dist / "README.md").write_bytes((SRC / "README.md").read_bytes().replace(b"\r\n", b"\n"))
    workflow = dist / ".github" / "workflows"
    workflow.mkdir(parents=True)
    (workflow / "ci.yml").write_text(CI_WORKFLOW, encoding="utf-8", newline="\n")


def run_selftests(plugin: Path) -> None:
    env = {**os.environ, "PYTHONPATH": str(plugin / "engine"), "PYTHONUTF8": "1",
           "PYTHONDONTWRITEBYTECODE": "1", "CLAUDE_PLUGIN_ROOT": str(plugin)}
    env.pop("KEEL_VAULT", None)
    done = subprocess.run([sys.executable, "-m", "keel", "selftest"], cwd=plugin, env=env,
                          capture_output=True, text=True, encoding="utf-8", errors="replace")
    if done.returncode != 0:
        raise BuildError("селфтести на дереві dist упали:\n" + done.stderr[-3000:])
    match = re.search(r"Ran (\d+) tests?", done.stderr)
    return int(match.group(1)) if match else 0


def make_zip(tree: Path, target: Path) -> None:
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(tree.rglob("*")):
            if path.is_file():
                info = zipfile.ZipInfo(f"keel-marketplace/{path.relative_to(tree).as_posix()}", ZIP_EPOCH)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (0o755 if path.suffix == ".sh" or path.name == "pre-commit" else 0o644) << 16
                archive.writestr(info, path.read_bytes())


def verify_zip(tree: Path, target: Path) -> str:
    with zipfile.ZipFile(target) as archive:
        names = {n.removeprefix("keel-marketplace/") for n in archive.namelist()}
        files = {p.relative_to(tree).as_posix() for p in tree.rglob("*") if p.is_file()}
        if names != files:
            raise BuildError(f"ZIP і дерево розходяться: {sorted(names ^ files)[:5]}")
        for name in files:
            if archive.read(f"keel-marketplace/{name}") != (tree / name).read_bytes():
                raise BuildError(f"вміст ZIP відрізняється: {name}")
    return hashlib.sha256(target.read_bytes()).hexdigest()


def write_report(version: str, files: list[str], skipped: list[str], tree: Path, sha: str, tests: int,
                 denylist_size: int, previous: set[str], identity_size: int = 0, repo_files: int = 0) -> None:
    current = set(files)
    lines = [
        f"# Звіт збірки Keel {version}", "",
        "Цей звіт треба прочитати ПЕРЕД будь-якою передачею. Збірка нічого не публікує.", "",
        "| Перевірка | Результат |", "|---|---|",
        f"| Особисті маркери (термінів у denylist: {denylist_size}; публічна ідентичність автора: {identity_size} рядки) | 0 збігів |",
        f"| Ті самі маркери в усіх файлах git-репозиторію ({repo_files}) | 0 збігів |",
        "| Секрети | 0 знахідок |", "| CRLF, незаповнені підстановки, заборонені теки | 0 |",
        f"| Селфтести на дереві dist | {tests} пройдено |",
        f"| ZIP = дерево | так, SHA-256 `{sha}` |", "",
        "Denylist ловить лише те, що в ньому записано. Автоматика не замінює перегляд людиною.", "",
        f"## Зміни проти попередньої збірки: +{len(current - previous)} / -{len(previous - current)}", "",
    ]
    lines += [f"- додано `{f}`" for f in sorted(current - previous)[:50]]
    lines += [f"- прибрано `{f}`" for f in sorted(previous - current)[:50]]
    lines += ["", f"## Файли у пакеті ({len(files)})", ""]
    for name in files:
        data = (tree / name).read_bytes()
        lines.append(f"- `{name}` ({len(data)} Б, {hashlib.sha256(data).hexdigest()[:10]})")
    lines += ["", f"## Поза allowlist, не потрапили ({len(skipped)})", ""]
    lines += [f"- `{name}`" for name in skipped]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    (ROOT / "dist" / "files.json").write_text(json.dumps(files, indent=0), encoding="utf-8", newline="\n")


def build(denylist_path: Path, run_tests: bool = True) -> dict:
    from keel import secretscan  # noqa: PLC0415 - шлях додано вище

    config = tomllib.loads((ROOT / "build" / "allowlist.toml").read_text(encoding="utf-8"))
    params = tomllib.loads((ROOT / "build" / "params.toml").read_text(encoding="utf-8"))
    identity = public_identity(params)
    params = {k: v for k, v in params.items() if isinstance(v, str)}
    terms = load_denylist(denylist_path)
    manifest = json.loads((SRC / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    version = manifest["version"]
    previous_list = ROOT / "dist" / "files.json"
    previous = set(json.loads(previous_list.read_text(encoding="utf-8"))) if previous_list.exists() else set()

    if ROOT / "dist" in DIST.parents and (ROOT / "dist").exists():
        git_dir = DIST / ".git"
        keep = git_dir.exists()
        if DIST.exists():
            for item in DIST.iterdir():
                if item.name == ".git":
                    continue
                shutil.rmtree(item) if item.is_dir() else item.unlink()
        ZIP_PATH.unlink(missing_ok=True)
        REPORT.unlink(missing_ok=True)
        del keep
    DIST.mkdir(parents=True, exist_ok=True)

    files, skipped = select_files(SRC, config["include"])
    if not files:
        raise BuildError("allowlist не вибрав жодного файлу")
    plugin = DIST / "plugins" / params["PLUGIN_NAME"]
    for name in files:
        source, target = SRC / name, plugin / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.suffix.lower() in TEXT_SUFFIXES:
            text = source.read_bytes().decode("utf-8").replace("\r\n", "\n")
            target.write_bytes(apply_params(text, params).encode("utf-8"))
        else:
            target.write_bytes(source.read_bytes())
    write_marketplace(DIST, params, version)

    tree_excluding_git = _Tree(DIST)
    errors = check_text_rules(tree_excluding_git.path)
    if errors:
        raise BuildError("правила тексту:\n" + "\n".join(errors[:30]))
    hits = check_denylist(tree_excluding_git.path, terms, identity)
    if hits:
        raise BuildError("особисті маркери:\n" + "\n".join(hits[:50]))
    # Фікстури тестів сканера побудовано конкатенацією, тому в сирому тексті їх немає.
    found = secretscan.scan_paths([tree_excluding_git.path])
    if found:
        raise BuildError("секрети:\n" + "\n".join(f"{f.file}:{f.line} {f.type}" for f in found[:30]))
    tree_excluding_git.close()
    repo_files, repo_hits = check_repo(terms, identity)
    if repo_hits:
        raise BuildError("особисті маркери в репозиторії:\n" + "\n".join(repo_hits[:50]))
    tests = run_selftests(plugin) if run_tests else 0
    if run_tests and tests == 0:
        raise BuildError("селфтести не запустились (Г52)")
    pure = _Tree(DIST)
    make_zip(pure.path, ZIP_PATH)
    sha = verify_zip(pure.path, ZIP_PATH)
    pure.close()
    write_report(version, files, skipped, plugin, sha, tests, len(terms), previous, len(identity), repo_files)
    return {"version": version, "files": len(files), "tests": tests, "sha256": sha, "report": str(REPORT)}


def check_repo(terms: list[str], identity: list[str]) -> tuple[int, list[str]]:
    """Публічний репозиторій це теж дистрибутив: та сама перевірка на всіх файлах, що в git."""
    listed = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT,
                            capture_output=True, check=True).stdout.decode("utf-8").split("\0")
    import tempfile  # noqa: PLC0415
    with tempfile.TemporaryDirectory() as tmp:
        tree = Path(tmp)
        names = [n for n in listed if n and (ROOT / n).is_file()]
        for name in names:
            target = tree / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / name).read_bytes())
        return len(names), check_denylist(tree, terms, identity)


class _Tree:
    """Копія дерева без .git: перевірки й ZIP не мають бачити внутрішню історію."""

    def __init__(self, source: Path):
        import tempfile  # noqa: PLC0415
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "tree"
        shutil.copytree(source, self.path, ignore=shutil.ignore_patterns(".git", "__pycache__"))

    def close(self) -> None:
        self._tmp.cleanup()


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser()
    parser.add_argument("--denylist", type=Path, default=DEFAULT_DENYLIST)
    parser.add_argument("--no-tests", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(build(args.denylist, not args.no_tests), ensure_ascii=False, indent=2))
        return 0
    except BuildError as exc:
        print(f"ЗБІРКУ ЗУПИНЕНО: {exc}", file=sys.stderr)
        REPORT.unlink(missing_ok=True)
        ZIP_PATH.unlink(missing_ok=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
