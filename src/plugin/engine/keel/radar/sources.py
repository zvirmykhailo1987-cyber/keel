"""Безкоштовні джерела без ключів: OSV, реєстри пакетів, endoflife.date, стрічки релізів."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from ..fetch import fetch
from . import versions
from .lockfiles import Dep

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{}"
BATCH_SIZE = 500
ORDER = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1}


@dataclass
class Vuln:
    id: str
    summary: str
    severity: str  # CRITICAL/HIGH/MODERATE/LOW/UNKNOWN
    fixed: list[str]
    url: str


def osv_query(deps: list[Dep], cache_dir: Path | None = None) -> dict[tuple[str, str, str], list[str]]:
    """Повертає {(екосистема, назва, версія): [id]}. Помилка мережі піднімається далі:
    радар має сказати «джерело недоступне», а не «вразливостей немає»."""
    out: dict[tuple[str, str, str], list[str]] = {}
    for start in range(0, len(deps), BATCH_SIZE):
        batch = deps[start:start + BATCH_SIZE]
        pending = [(dep, None) for dep in batch]
        while pending:
            queries = []
            for dep, token in pending:
                query = {"package": {"name": dep.name, "ecosystem": dep.ecosystem}, "version": dep.version}
                if token:
                    query["page_token"] = token
                queries.append(query)
            body = json.dumps({"queries": queries}, sort_keys=True).encode()
            reply = fetch(OSV_BATCH, method="POST", data=body,
                          headers={"Content-Type": "application/json"}, timeout=60).json()
            next_pending = []
            for (dep, _), result in zip(pending, reply.get("results", [])):
                key = (dep.ecosystem, dep.name, dep.version)
                out.setdefault(key, []).extend(v["id"] for v in result.get("vulns") or [])
                if result.get("next_page_token"):
                    next_pending.append((dep, result["next_page_token"]))
            pending = next_pending
    return out


def _severity(record: dict) -> str:
    specific = str(record.get("database_specific", {}).get("severity", "")).upper()
    if specific in ORDER:
        return specific
    for affected in record.get("affected", []):
        specific = str(affected.get("ecosystem_specific", {}).get("severity", "")).upper()
        if specific in ORDER:
            return specific
    return "UNKNOWN"


def _fixed_versions(record: dict, dep: Dep) -> list[str]:
    fixed: set[str] = set()
    for affected in record.get("affected", []):
        package = affected.get("package", {})
        if package.get("name") != dep.name or package.get("ecosystem") != dep.ecosystem:
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if event.get("fixed"):
                    fixed.add(event["fixed"])
    return sorted(fixed)


def osv_vuln(vuln_id: str, dep: Dep, cache_dir: Path | None = None) -> Vuln:
    record = fetch(OSV_VULN.format(urllib.parse.quote(vuln_id)), cache_dir=cache_dir, timeout=30).json()
    return Vuln(vuln_id, record.get("summary") or (record.get("details") or "")[:160],
                _severity(record), _fixed_versions(record, dep), f"https://osv.dev/vulnerability/{vuln_id}")


def latest_version(dep: Dep, cache_dir: Path | None = None) -> str | None:
    """Найновіша стабільна версія або None, якщо реєстр такої екосистеми не підтримано."""
    name, quoted = dep.name, urllib.parse.quote(dep.name, safe="")
    eco = dep.ecosystem
    if eco == "npm":
        return fetch(f"https://registry.npmjs.org/{name.replace('/', '%2F')}/latest",
                     cache_dir=cache_dir).json().get("version")
    if eco == "PyPI":
        return fetch(f"https://pypi.org/pypi/{quoted}/json", cache_dir=cache_dir).json()["info"]["version"]
    if eco == "crates.io":
        crate = fetch(f"https://crates.io/api/v1/crates/{quoted}", cache_dir=cache_dir).json()["crate"]
        return crate.get("max_stable_version") or crate.get("newest_version")
    if eco == "Go":
        escaped = re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), name)
        return fetch(f"https://proxy.golang.org/{escaped}/@latest", cache_dir=cache_dir).json()["Version"]
    if eco == "Packagist":
        items = fetch(f"https://repo.packagist.org/p2/{name}.json", cache_dir=cache_dir).json()
        return versions.newest([p["version"] for p in items["packages"].get(name, [])])
    if eco == "RubyGems":
        return fetch(f"https://rubygems.org/api/v1/versions/{quoted}/latest.json",
                     cache_dir=cache_dir).json().get("version")
    if eco == "NuGet":
        listed = fetch(f"https://api.nuget.org/v3-flatcontainer/{quoted.lower()}/index.json",
                       cache_dir=cache_dir).json()
        return versions.newest(listed.get("versions", []))
    if eco == "Maven":
        group, artifact = name.split(":", 1)
        reply = fetch("https://search.maven.org/solrsearch/select?q="
                      + urllib.parse.quote(f'g:"{group}" AND a:"{artifact}"')
                      + "&rows=1&wt=json", cache_dir=cache_dir).json()
        docs = reply.get("response", {}).get("docs", [])
        return docs[0].get("latestVersion") if docs else None
    return None


@dataclass
class EolStatus:
    product: str
    cycle: str
    eol: str | None  # дата або None, якщо дата невідома
    days_left: int | None
    version: str
    latest_cycle: str | None = None


def eol_status(product: str, version: str, today: dt.date, cache_dir: Path | None = None) -> EolStatus | None:
    cycles = fetch(f"https://endoflife.date/api/{product}.json", cache_dir=cache_dir).json()
    best = None
    for cycle in cycles:
        name = str(cycle.get("cycle", ""))
        if version == name or version.startswith(name + "."):
            if best is None or len(name) > len(str(best["cycle"])):
                best = cycle
    if best is None:
        return None
    eol = best.get("eol")
    if eol is False:
        return EolStatus(product, str(best["cycle"]), None, None, version, str(cycles[0].get("cycle")))
    if eol is True:
        return EolStatus(product, str(best["cycle"]), "вже завершено", -1, version, str(cycles[0].get("cycle")))
    when = dt.date.fromisoformat(str(eol))
    return EolStatus(product, str(best["cycle"]), when.isoformat(), (when - today).days, version,
                     str(cycles[0].get("cycle")))


ATOM = "{http://www.w3.org/2005/Atom}"


def github_releases(repo: str, cache_dir: Path | None = None) -> list[dict]:
    root = ET.fromstring(fetch(f"https://github.com/{repo}/releases.atom", cache_dir=cache_dir).body)
    items = []
    for entry in root.findall(f"{ATOM}entry"):
        link = entry.find(f"{ATOM}link")
        items.append({"id": entry.findtext(f"{ATOM}id", ""), "title": (entry.findtext(f"{ATOM}title") or "").strip(),
                      "url": link.get("href") if link is not None else "",
                      "updated": entry.findtext(f"{ATOM}updated", "")})
    return items


_TAGS = re.compile(r"<(script|style)[^>]*>.*?</\1>|<[^>]+>", re.S | re.I)


def page_text(html: str) -> str:
    return re.sub(r"\s+", " ", _TAGS.sub(" ", html)).strip()


def page_hash(url: str, cache_dir: Path | None = None) -> str:
    """Відбиток видимого тексту, щоб лічильники й токени в розмітці не давали хибних змін."""
    return hashlib.sha256(page_text(fetch(url, cache_dir=cache_dir).text).encode()).hexdigest()[:16]
