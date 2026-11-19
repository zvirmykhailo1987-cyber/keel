# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Mykhailo Zvir

r"""Break the guard and the scanner on purpose and check that the self-tests notice. Writes docs/mutation-results.json.

Coverage says a line ran. This says a test fails when the line is wrong. Each mutation removes one detection or one
block from a temporary copy of the engine, and the self-tests run against that copy. A mutation nothing catches is
reported as "survived", not hidden, and the script exits non-zero. Equivalent mutants are left out on purpose:
removing the `--config-env` alternative survived the first run (19.11.2026) because `\bconfig\b` already matches inside
`--config-env`, so no test can tell the two apart. Stdlib only, no network:

    python tests/mutation_check.py
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUARD = "keel/guard.py"
SCAN = "keel/secretscan.py"
# The guard tests go first, so a caught mutation usually stops within seconds (-f).
MODULES = ["test_guard", "test_growth", "test_flow", "test_package", "test_radar", "test_runtime", "test_scheduler"]

MUTATIONS = [
    ("--no-verify on push/merge/rebase is no longer seen", GUARD,
     r"\b(?:commit|push|merge|am|rebase|cherry-pick)\b{_SEGMENT}\s--no-veri\w*|",
     r"\b(?:commit|push|merge|am|rebase|cherry-pick)\b{_SEGMENT}\s--no-verify-never\w*|"),
    ("`git commit -n` (short flag cluster) is no longer seen", GUARD,
     r"\s-(?!-)[a-zA-Z]*n[a-zA-Z]*(?:\s|$)",
     r"\s-(?!-)[a-zA-Z]*N0[a-zA-Z]*(?:\s|$)"),
    ("`git commit-tree` writes history unseen", GUARD,
     "(?:fast-import|commit-tree|update-ref)", "(?:fast-import|update-ref)"),
    ("`git update-ref` moves a branch unseen", GUARD,
     "(?:fast-import|commit-tree|update-ref)", "(?:fast-import|commit-tree)"),
    ("`git am` applies mail patches unseen", GUARD,
     r"(?<![-\w.])am\b(?!", r"(?<![-\w.])am_never\b(?!"),
    ("A patch applied before the commit is not read", GUARD,
     "found = _patch_findings(text, cwd)", "found = []"),
    ("`git send-email` sends code out unseen", GUARD,
     "    if GIT_OUTBOUND.search(text):\n", "    if False:\n"),
    ("core.hooksPath can be redirected", GUARD,
     r"(?i:core\.hookspath|alias\.|", r"(?i:alias\.|"),
    ("`git config <key>` is no longer seen as tampering", GUARD,
     r"(?:\bconfig\b|\s-c\s|", r"(?:\s-c\s|"),
    ("KEEL_ALLOW_SECRET can be set by the model", GUARD,
     "GIT_EXEC_PATH|KEEL_ALLOW_SECRET|ANTHROPIC_BASE_URL)", "GIT_EXEC_PATH|ANTHROPIC_BASE_URL)"),
    ("`gh api -X PATCH` writes refs unseen", GUARD,
     '{"PUT", "POST", "PATCH"}', '{"PUT", "POST"}'),
    ("A notebook cell is not scanned", GUARD,
     '    return tool_input.get("new_source", "")', '    return ""'),
    ("A crashed check becomes a pass", GUARD,
     "    return 2 if _cheap_fail_closed(raw) else 0  # ", "    return 0  # "),
    ("A checker error lets a write or commit through", GUARD,
     "        if must_fail_closed(payload):\n", "        if False:\n"),
    ("A key split into joined literals is missed", SCAN,
     "    if not binary and _JOIN.search(text):\n", "    if False:\n"),
    ("A base64/hex-encoded key is missed", SCAN,
     "shapes = _shapes(line) or ([] if binary else _decoded(line))", "shapes = _shapes(line)"),
    ("UTF-16 without BOM (NUL between letters) is missed", SCAN,
     '        return text.replace("\\x00", "")', "        return text"),
    ("UTF-16 with BOM is read as UTF-8", SCAN,
     'return data.decode("utf-16", errors="ignore")', 'return data.decode("utf-8", errors="ignore")'),
    ("Untracked files are skipped by `git add . && git commit`", SCAN,
     "            findings += scan_text(text, name)\n    return findings", "            pass\n    return findings"),
    ("Commits outside every branch are not checked on ref update", SCAN,
     'commits = _git(["rev-list", f"--max-count={limit}", new, "--not", "--branches", "--tags", "--remotes"], repo).split()',
     "commits = []"),
]


def copy_engine(target: Path) -> Path:
    skip = {".git", "dist", "__pycache__", ".ruff_cache", ".coverage", "htmlcov"}
    shutil.copytree(ROOT, target, ignore=lambda _d, names: [n for n in names if n in skip or n.startswith(".coverage.")])
    return target / "src" / "plugin" / "engine"


def run_tests(engine: Path) -> tuple[bool, str]:
    env = {**os.environ, "PYTHONPATH": str(engine), "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8",
           "PYTHONDONTWRITEBYTECODE": "1"}
    for name in ("COVERAGE_PROCESS_START", "COVERAGE_PROCESS_CONFIG"):
        env.pop(name, None)
    done = subprocess.run([sys.executable, "-m", "unittest", "-f", *(f"keel_tests.{m}" for m in MODULES)],
                          cwd=engine, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
    failed = re.findall(r"^(?:FAIL|ERROR): (\S+) \(([\w.]+)\)", done.stderr, re.M)
    return done.returncode == 0, (failed[0][1].removeprefix("keel_tests.") if failed else "")


def main() -> int:
    results = []
    with tempfile.TemporaryDirectory(prefix="keel-mutation-") as tmp:
        engine = copy_engine(Path(tmp) / "copy")
        passed, failing = run_tests(engine)
        if not passed:
            raise SystemExit(f"The unmodified copy does not pass ({failing}), so nothing here could be trusted.")
        for name, relative, old, new in MUTATIONS:
            path = engine / relative
            original = path.read_text(encoding="utf-8")
            if original.count(old) != 1:
                raise SystemExit(f"Mutation does not apply exactly once, fix the script: {name}")
            path.write_text(original.replace(old, new, 1), encoding="utf-8", newline="\n")
            passed, caught_by = run_tests(engine)
            path.write_text(original, encoding="utf-8", newline="\n")
            results.append({"bug": name, "file": f"src/plugin/engine/{relative}", "caught": not passed,
                            "caught_by": caught_by or None})
            print("caught  " if not passed else "SURVIVED", name, caught_by, flush=True)
    summary = {"measured": dt.date.today().isoformat(), "bugs_injected": len(results),
               "caught": sum(row["caught"] for row in results), "results": results}
    (ROOT / "docs" / "mutation-results.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
                                                          encoding="utf-8", newline="\n")
    print(summary["caught"], "of", summary["bugs_injected"])
    return 0 if summary["caught"] == summary["bugs_injected"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
