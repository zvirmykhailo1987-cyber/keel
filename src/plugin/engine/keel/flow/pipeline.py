"""Перетворює знахідки радара на дії й картки. Детерміновано.

До людини доходить лише те, що потребує рішення: важливі вразливості й близький EOL.
Решта лишається у звіті, бо черга, що росте швидше, ніж її читають, не фільтрує нічого (G51)."""
from __future__ import annotations

from ..paths import Vault
from ..radar import versions
from ..radar.sources import ORDER as _SEVERITY
from .depbump import ProjectPolicy
from .executor import Executor

CARD_SEVERITIES = {"CRITICAL", "HIGH", "UNKNOWN"}
EOL_CARD_DAYS = 60
SOURCE_SILENT_RUNS = 3


def _lowest_fix(version: str, fixed: list[str]) -> str | None:
    usable = [f for f in fixed if versions.gap(version, f) in {"patch", "minor", "major"}]
    return min(usable, key=lambda v: versions.parse(v) + (0,) * (6 - len(versions.parse(v))), default=None)


def group_vulns(findings: list[dict]) -> list[dict]:
    groups: dict[tuple, dict] = {}
    for item in findings:
        if item["kind"] != "vuln":
            continue
        data = item["data"]
        key = (item["project"], data["ecosystem"], data["package"], data["version"])
        group = groups.setdefault(key, {"project": item["project"], "ecosystem": data["ecosystem"],
                                        "package": data["package"], "version": data["version"],
                                        "vulns": [], "severities": [], "fixed": set(), "url": item["url"]})
        group["vulns"].append(data["vuln"])
        group["severities"].append(data["severity"])
        group["fixed"].update(data.get("fixed") or [])
    return list(groups.values())


def _policy_enabled(executor: Executor, project: str) -> bool:
    try:
        return ProjectPolicy.load(executor._project_root(project)).enabled
    except ValueError:
        return False


def process(vault: Vault, new_findings: list[dict], executor: Executor | None = None) -> list[dict]:
    executor = executor or Executor(vault)
    results = []
    for group in group_vulns(new_findings):
        worst = max(group["severities"], key=lambda s: _SEVERITY.get(s, 3))
        if worst not in CARD_SEVERITIES:
            continue
        fix = _lowest_fix(group["version"], sorted(group["fixed"]))
        title = (f"{group['project']}: {group['package']} {group['version']} має {len(group['vulns'])} "
                 f"вразливість(ей), найвища {worst}")
        gap = versions.gap(group["version"], fix) if fix else None
        if gap == "patch" and _policy_enabled(executor, group["project"]):
            results.append(executor.propose({
                "action": "dep_patch_branch", "why": title, "source": group["url"],
                "params": {"project": group["project"], "ecosystem": group["ecosystem"], "package": group["package"],
                           "from_version": group["version"], "to_version": fix}}, origin="radar"))
            continue
        advice = f"Виправлено у {fix} ({gap})." if fix else "Версії з виправленням у джерелі не вказано."
        results.append(executor.propose({
            "action": "human_decision", "why": advice, "source": group["url"],
            "params": {"question": title}}, origin="radar"))
    for item in new_findings:
        kind, data = item["kind"], item.get("data", {})
        if kind == "outdated" and data.get("gap") == "patch" and data.get("direct") \
                and _policy_enabled(executor, item["project"]):
            results.append(executor.propose({
                "action": "dep_patch_branch", "why": item["title"], "source": "radar",
                "params": {"project": item["project"], "ecosystem": data["ecosystem"], "package": data["package"],
                           "from_version": data["version"], "to_version": data["latest"]}}, origin="radar"))
        elif kind == "eol" and data.get("days_left") is not None and data["days_left"] <= EOL_CARD_DAYS:
            results.append(executor.propose({
                "action": "human_decision", "source": item["url"],
                "why": f"Найновіша гілка: {data.get('latest_cycle') or 'немає даних'}.",
                "params": {"question": f"{item['project']}: {item['title']}"}}, origin="radar"))
    return results


def silent_sources(vault: Vault, source_errors: dict[str, int], executor: Executor | None = None) -> list[dict]:
    """Джерело, яке кілька прогонів поспіль не відповідає, не повинно зникати непомітно (G39)."""
    executor = executor or Executor(vault)
    return [executor.propose({
        "action": "human_decision", "source": source,
        "why": "Поки джерело мовчить, Radar цей клас ризиків не бачить.",
        "params": {"question": f"Джерело {source} не відповідає вже {count} прогонів поспіль"}}, origin="radar")
        for source, count in source_errors.items() if count >= SOURCE_SILENT_RUNS]
