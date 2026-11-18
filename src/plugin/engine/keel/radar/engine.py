"""Збирає знахідки по проєктах. Детерміновано, без LLM.

Головне правило чесності: якщо джерело не відповіло, у звіті стоїть «не перевірено»,
а не «0 проблем». Порожній результат без перевірки дорівнює брехні (G15, G39)."""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .. import clock
from ..fetch import FetchError
from ..fsutil import read_json, write_json, write_text
from ..journal import Journal
from ..paths import Vault
from ..stacks import Stack, detect, detect_frameworks, load_stacks
from . import sources, versions
from .lockfiles import Dep, parse_project

# Години між опитуваннями кожного класу джерел. Tick щогодини, але реєстри шануємо.
CADENCE_HOURS = {"osv": 6, "registry": 24, "eol": 168, "feed": 24, "page": 24}
MAX_LATEST_LOOKUPS = 150
DEFAULT_WATCH = ["anthropics/claude-code"]
SEVERITY_SCORE = {"CRITICAL": 100, "HIGH": 75, "MODERATE": 50, "MEDIUM": 50, "LOW": 25, "UNKNOWN": 60}
GAP_SCORE = {"major": 30, "minor": 12, "patch": 8}


@dataclass
class Finding:
    id: str
    kind: str  # vuln, eol, outdated, release, page_changed, incomplete
    project: str
    title: str
    score: int
    url: str = ""
    data: dict = field(default_factory=dict)
    first_seen: str = ""


def _fid(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:12]


def vuln_score(severity: str, direct: bool | None) -> int:
    """UNKNOWN вище за LOW: невідома важкість не є низькою (G15)."""
    base = SEVERITY_SCORE.get(severity, 60)
    return base + (10 if direct else 0)


class RadarState:
    def __init__(self, vault: Vault):
        self.path = vault.state / "radar.json"
        self.data = read_json(self.path) or {}
        self.data.setdefault("last", {})
        self.data.setdefault("findings", {})
        self.data.setdefault("feeds", {})
        self.data.setdefault("pages", {})
        self.data.setdefault("source_errors", {})

    def due(self, key: str, cadence: str) -> bool:
        last = self.data["last"].get(key)
        return last is None or clock.age_days(last) * 24 >= CADENCE_HOURS[cadence] - 0.01

    def mark(self, key: str) -> None:
        self.data["last"][key] = clock.iso()

    def save(self) -> None:
        write_json(self.path, self.data)


@dataclass
class ScanOutcome:
    findings: list[Finding] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    unchecked: list[str] = field(default_factory=list)
    deps: int = 0
    stacks: list[str] = field(default_factory=list)


def _runtime_version(root: Path, filename: str, pattern: str) -> str | None:
    for candidate in [root / filename]:
        if candidate.is_file():
            match = re.search(pattern, candidate.read_text(encoding="utf-8", errors="replace"), re.M)
            if match:
                return match.group(1)
    return None


def _note_error(outcome: ScanOutcome, source: str, exc: Exception) -> None:
    kind = getattr(exc, "kind", type(exc).__name__)
    outcome.errors.append({"source": source, "kind": kind, "detail": str(exc)[:200]})


def scan_vulns(project: str, deps: list[Dep], outcome: ScanOutcome, cache: Path) -> None:
    if not deps:
        return
    try:
        hits = sources.osv_query(deps, cache)
    except (FetchError, ValueError, KeyError) as exc:
        _note_error(outcome, "osv", exc)
        outcome.unchecked.append(f"{project}: вразливості НЕ перевірено ({len(deps)} залежностей)")
        return
    by_key = {(d.ecosystem, d.name, d.version): d for d in deps}
    for key, ids in hits.items():
        dep = by_key[key]
        for vuln_id in ids:
            try:
                vuln = sources.osv_vuln(vuln_id, dep, cache)
            except (FetchError, ValueError) as exc:
                _note_error(outcome, "osv-detail", exc)
                vuln = sources.Vuln(vuln_id, "деталі недоступні", "UNKNOWN", [],
                                    f"https://osv.dev/vulnerability/{vuln_id}")
            outcome.findings.append(Finding(
                _fid("vuln", project, dep.ecosystem, dep.name, dep.version, vuln_id), "vuln", project,
                f"{dep.name} {dep.version}: {vuln.id} [{vuln.severity}] {vuln.summary}".strip(),
                vuln_score(vuln.severity, dep.direct), vuln.url,
                {"ecosystem": dep.ecosystem, "package": dep.name, "version": dep.version, "vuln": vuln.id,
                 "severity": vuln.severity, "fixed": vuln.fixed, "direct": dep.direct, "source": dep.source}))


def scan_outdated(project: str, deps: list[Dep], outcome: ScanOutcome, cache: Path) -> None:
    candidates = [d for d in deps if d.direct] or deps
    skipped = max(0, len(candidates) - MAX_LATEST_LOOKUPS)
    if skipped:
        outcome.unchecked.append(f"{project}: застарілість перевірено не для {skipped} залежностей (ліміт за прогін)")
    failures = 0
    for dep in candidates[:MAX_LATEST_LOOKUPS]:
        try:
            latest = sources.latest_version(dep, cache)
        except (FetchError, ValueError, KeyError) as exc:
            failures += 1
            _note_error(outcome, f"registry:{dep.ecosystem}", exc)
            continue
        if not latest or versions.is_prerelease(latest):
            continue
        gap = versions.gap(dep.version, latest)
        if gap in GAP_SCORE:
            outcome.findings.append(Finding(
                _fid("outdated", project, dep.ecosystem, dep.name, latest), "outdated", project,
                f"{dep.name}: {dep.version} → {latest} ({gap})", GAP_SCORE[gap], "",
                {"ecosystem": dep.ecosystem, "package": dep.name, "version": dep.version, "latest": latest,
                 "gap": gap, "direct": dep.direct, "source": dep.source}))
    if failures:
        outcome.unchecked.append(f"{project}: реєстр не відповів для {failures} залежностей")


def scan_eol(project: str, root: Path, stacks: list[Stack], deps: list[Dep], outcome: ScanOutcome, cache: Path) -> None:
    today = clock.now().date()
    names = {d.name for d in deps}
    dep_version = {d.name: d.version for d in deps}
    for stack in stacks:
        targets: list[tuple[str, str]] = []
        for filename, spec in stack.runtime_files.items():
            product, _, pattern = spec.partition("|")
            version = _runtime_version(root, filename, pattern)
            if version:
                targets.append((product, version))
        for product in detect_frameworks(root, stack, names):
            package = next(iter(set(stack.frameworks[product]) & names))
            targets.append((product, dep_version[package]))
        for product, version in targets:
            try:
                status = sources.eol_status(product, version, today, cache)
            except (FetchError, ValueError, KeyError) as exc:
                _note_error(outcome, "eol", exc)
                outcome.unchecked.append(f"{project}: EOL {product} не перевірено")
                continue
            if status is None:
                outcome.unchecked.append(f"{project}: {product} {version} не знайдено в endoflife.date")
            elif status.days_left is not None and status.days_left <= 180:
                score = 80 if status.days_left < 0 else 55 if status.days_left <= 60 else 35
                state = "уже без підтримки" if status.days_left < 0 else f"кінець підтримки {status.eol}"
                outcome.findings.append(Finding(
                    _fid("eol", project, product, status.cycle), "eol", project,
                    f"{product} {status.cycle}: {state}", score, f"https://endoflife.date/{product}",
                    {"product": product, "cycle": status.cycle, "eol": status.eol, "days_left": status.days_left,
                     "latest_cycle": status.latest_cycle}))


def scan_feeds(repos: list[str], state: RadarState, outcome: ScanOutcome, cache: Path) -> None:
    for repo in repos:
        try:
            items = sources.github_releases(repo, cache)
        except (FetchError, ValueError, Exception) as exc:  # noqa: BLE001 - парсер XML теж може впасти
            _note_error(outcome, f"feed:{repo}", exc)
            continue
        seen = state.data["feeds"].get(repo)
        ids = [i["id"] for i in items]
        if seen is None:
            # Перший прогін лише запам'ятовує: історія релізів не є новиною.
            state.data["feeds"][repo] = ids[:50]
            continue
        for item in items:
            if item["id"] not in seen:
                outcome.findings.append(Finding(
                    _fid("release", repo, item["id"]), "release", "*", f"{repo}: {item['title']}", 15,
                    item["url"], {"repo": repo, "updated": item["updated"]}))
        state.data["feeds"][repo] = (ids + [s for s in seen if s not in ids])[:100]


def scan_pages(pages: list[str], state: RadarState, outcome: ScanOutcome, cache: Path) -> None:
    for url in pages:
        try:
            digest = sources.page_hash(url, cache)
        except FetchError as exc:
            _note_error(outcome, f"page:{url}", exc)
            continue
        previous = state.data["pages"].get(url)
        state.data["pages"][url] = digest
        if previous and previous != digest:
            outcome.findings.append(Finding(_fid("page", url, digest), "page_changed", "*",
                                            f"Сторінка змінилась: {url}", 20, url))


def scan_project(name: str, root: Path, state: RadarState, cache: Path, stacks: list[Stack] | None = None,
                 force: bool = False) -> ScanOutcome:
    outcome = ScanOutcome()
    found = detect(root, stacks)
    outcome.stacks = [s.id for s in found]
    parsed = parse_project(root)
    outcome.deps = len(parsed.deps)
    for item in parsed.incomplete:
        outcome.findings.append(Finding(_fid("incomplete", name, item["file"]), "incomplete", name,
                                        f"{item['file']}: {item['reason']}", 10, "", item))
    if force or state.due(f"osv:{name}", "osv"):
        before = len(outcome.errors)
        scan_vulns(name, parsed.deps, outcome, cache)
        if len(outcome.errors) == before:
            state.mark(f"osv:{name}")
    if force or state.due(f"registry:{name}", "registry"):
        scan_outdated(name, parsed.deps, outcome, cache)
        state.mark(f"registry:{name}")
    if force or state.due(f"eol:{name}", "eol"):
        scan_eol(name, root, found, parsed.deps, outcome, cache)
        state.mark(f"eol:{name}")
    return outcome


SCANNED_KINDS_BY_CADENCE = {"osv": "vuln", "registry": "outdated", "eol": "eol"}


def merge_findings(state: RadarState, project: str, outcome: ScanOutcome, ran: set[str]) -> list[Finding]:
    """Повертає нові. Знахідка зникає зі стану лише якщо її клас у цьому прогоні справді
    перевірено: збій OSV не може «закрити» вразливість (G20)."""
    stored = state.data["findings"]
    fresh: list[Finding] = []
    current_ids = {f.id for f in outcome.findings}
    for finding in outcome.findings:
        if finding.id in stored:
            stored[finding.id].update(title=finding.title, score=finding.score, data=finding.data)
            continue
        finding.first_seen = clock.iso()
        stored[finding.id] = asdict(finding)
        fresh.append(finding)
    for fid, item in list(stored.items()):
        if item["project"] == project and item["kind"] in ran and fid not in current_ids:
            del stored[fid]
    return fresh


def _render_report(state: RadarState, errors: list[dict], unchecked: list[str], projects: dict) -> str:
    items = sorted(state.data["findings"].values(), key=lambda f: -f["score"])
    lines = [f"# Radar: звіт на {clock.iso()}", ""]
    if errors or unchecked:
        lines += ["## ⚠ Перевірено не все", ""]
        lines += [f"- {u}" for u in unchecked]
        lines += [f"- джерело `{e['source']}`: {e['kind']}" for e in errors[:20]]
        lines.append("")
    lines += ["## Проєкти", ""]
    for name, info in projects.items():
        lines.append(f"- **{name}**: стеки {', '.join(info['stacks']) or 'не визначено'}, залежностей {info['deps']}")
    if not projects:
        lines.append("- Немає підключених проєктів. Запусти `/keel:init-project` у репозиторії.")
    lines += ["", f"## Знахідки ({len(items)})", ""]
    if not items:
        lines.append("Знахідок немає." if not (errors or unchecked) else
                     "Знахідок немає, але перевірка неповна: див. розділ вище.")
    for item in items[:100]:
        link = f" ([джерело]({item['url']}))" if item.get("url") else ""
        lines.append(f"- `{item['score']:>3}` {item['kind']} · {item['project']}: {item['title']}{link}")
    if len(items) > 100:
        lines.append(f"- … ще {len(items) - 100}")
    return "\n".join(lines) + "\n"


def load_projects(vault: Vault) -> dict[str, str]:
    return read_json(vault.projects_file) or {}


def run(vault: Vault, force: bool = False, stacks: list[Stack] | None = None) -> dict:
    vault.init()
    state = RadarState(vault)
    journal = Journal(vault.journal, vault.snapshots)
    cache = vault.cache / "http"
    stacks = stacks or load_stacks()
    all_new: list[Finding] = []
    errors: list[dict] = []
    unchecked: list[str] = []
    info: dict[str, dict] = {}
    watch: set[str] = set(DEFAULT_WATCH)
    for name, raw_path in load_projects(vault).items():
        root = Path(raw_path)
        if not root.is_dir():
            unchecked.append(f"{name}: теку не знайдено ({raw_path})")
            continue
        due = {k for k in SCANNED_KINDS_BY_CADENCE if force or state.due(f"{k}:{name}", k)}
        outcome = scan_project(name, root, state, cache, stacks, force)
        ran = {SCANNED_KINDS_BY_CADENCE[k] for k in due}
        ran.add("incomplete")
        if any(e["source"].startswith("osv") for e in outcome.errors):
            ran.discard("vuln")
        if any(e["source"].startswith("registry") for e in outcome.errors):
            ran.discard("outdated")
        if any(e["source"] == "eol" for e in outcome.errors):
            ran.discard("eol")
        all_new += merge_findings(state, name, outcome, ran)
        errors += outcome.errors
        unchecked += outcome.unchecked
        info[name] = {"stacks": outcome.stacks, "deps": outcome.deps}
        for stack in stacks:
            if stack.id in outcome.stacks:
                watch.update(stack.watch)
    global_outcome = ScanOutcome()
    if force or state.due("feeds", "feed"):
        scan_feeds(sorted(watch), state, global_outcome, cache)
        state.mark("feeds")
    settings = read_json(vault.settings_file) or {}
    pages = settings.get("watch_pages", [])
    if pages and (force or state.due("pages", "page")):
        scan_pages(pages, state, global_outcome, cache)
        state.mark("pages")
    all_new += merge_findings(state, "*", global_outcome, set())
    errors += global_outcome.errors
    # Стрічка, що довго мовчить через збої, має бути видимою, а не тихою (G39).
    for error in errors:
        count = state.data["source_errors"].get(error["source"], 0) + 1
        state.data["source_errors"][error["source"]] = count
    failed = {e["source"] for e in errors}
    for source in list(state.data["source_errors"]):
        if source not in failed:
            del state.data["source_errors"][source]
    state.save()
    for finding in all_new:
        journal.append("radar.finding", asdict(finding))
    if errors:
        journal.append("radar.source_errors", {"errors": errors[:20]})
    report = _render_report(state, errors, unchecked, info)
    write_text(vault.reports / "radar-latest.md", report)
    return {"new": [asdict(f) for f in all_new], "total": len(state.data["findings"]), "errors": errors,
            "unchecked": unchecked, "projects": info, "report": str(vault.reports / "radar-latest.md")}
