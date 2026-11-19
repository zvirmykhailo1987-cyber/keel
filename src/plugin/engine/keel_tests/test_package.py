# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Mykhailo Zvir

"""Цілісність пакета: навички, агенти, команди й граблі посилаються на те, що існує."""
import json
import re
import unittest
from pathlib import Path

from keel.cli import build_parser

ROOT = Path(__file__).resolve().parents[2]
CORE_SKILLS = {"code-review", "debugging", "testing", "security", "architecture", "data-migrations", "deploy-ci"}
ALL_SKILLS = CORE_SKILLS | {"performance", "observability", "frontend", "llm-apps", "mobile", "osint", "self-improve"}
AGENTS = {"brain", "architect", "builder", "reviewer", "tester", "debugger", "security", "release-gate", "researcher",
          "maintainer", "auditor", "onboarding"}
COMMANDS = {"setup", "init-project", "radar", "decide", "autopilot", "review", "osint", "learn", "retro", "adr",
            "doctor", "uninstall"}
BYPASS = re.compile(r"--dangerously-skip-permissions|bypassPermissions")


def frontmatter(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n") or "\n---\n" not in text[4:]:
        return {}
    block = text[4:text.index("\n---\n", 4)]
    return dict(line.split(":", 1) for line in block.splitlines() if ":" in line and not line.startswith(" "))


class TestSkills(unittest.TestCase):
    def test_all_present_with_description(self):
        found = {p.name for p in (ROOT / "skills").iterdir() if p.is_dir()}
        self.assertEqual(found, ALL_SKILLS)
        for name in ALL_SKILLS:
            meta = frontmatter(ROOT / "skills" / name / "SKILL.md")
            self.assertEqual(meta.get("name", "").strip(), name)
            self.assertGreater(len(meta.get("description", "")), 40, name)
            self.assertLessEqual(len(meta.get("description", "")), 1024, name)

    def test_required_sections(self):
        """Шаблон навички: без цих частин вона деградує до «поради»."""
        for name in ALL_SKILLS:
            text = (ROOT / "skills" / name / "SKILL.md").read_text(encoding="utf-8")
            for marker in ("overlay", "Tier", "людин", "/keel:retro", "G"):
                self.assertIn(marker, text, f"{name}: {marker}")

    def test_techniques_and_evals(self):
        for name in ALL_SKILLS:
            self.assertTrue((ROOT / "skills" / name / "references" / "techniques.md").is_file(), name)
            data = json.loads((ROOT / "skills" / name / "evals" / "evals.json").read_text(encoding="utf-8"))
            self.assertEqual(data["skill"], name)
            triggers = [c["should_trigger"] for c in data["cases"]]
            self.assertGreaterEqual(triggers.count(False), 2, name)
            self.assertGreaterEqual(triggers.count(True), 3, name)

    def test_pitfall_references_exist(self):
        existing = {p.name.split("-")[0] for p in (ROOT / "data" / "pitfalls").glob("G*.md")}
        for folder in ("skills", "agents", "commands"):
            for path in (ROOT / folder).rglob("*.md"):
                for ref in re.findall(r"\bG\d{1,2}\b", path.read_text(encoding="utf-8")):
                    self.assertIn(ref, existing, f"{path.name}: {ref}")

    def test_nothing_teaches_bypass(self):
        for folder in ("skills", "agents", "commands"):
            for path in (ROOT / folder).rglob("*.md"):
                for line in path.read_text(encoding="utf-8").splitlines():
                    if BYPASS.search(line):
                        self.assertRegex(line.lower(), "не |заборон|ніколи", f"{path.name}: {line[:80]}")


class TestPitfalls(unittest.TestCase):
    def test_index_lists_every_record_and_fits_session(self):
        files = {p.name.split("-")[0] for p in (ROOT / "data" / "pitfalls").glob("G*.md")}
        index = (ROOT / "data" / "pitfalls" / "INDEX.md").read_text(encoding="utf-8")
        listed = set(re.findall(r"^- (G\d+)", index, re.M))
        self.assertEqual(files, listed)
        self.assertGreaterEqual(len(files), 50)
        self.assertLessEqual(len(index), 5000)

    def test_session_shows_every_record(self):
        """G43 у дії: pre-flight не має мовчки обрізати реєстр."""
        from keel import session  # noqa: PLC0415
        titles = session._pitfall_titles()
        index = (ROOT / "data" / "pitfalls" / "INDEX.md").read_text(encoding="utf-8")
        self.assertEqual(len(titles), len(re.findall(r"^- G\d+", index, re.M)))

    def test_records_have_rule(self):
        for path in (ROOT / "data" / "pitfalls").glob("G*.md"):
            text = path.read_text(encoding="utf-8")
            self.assertIn("**Правило:**", text, path.name)


class TestAgents(unittest.TestCase):
    def test_all_present_valid(self):
        self.assertEqual({p.stem for p in (ROOT / "agents").glob("*.md")}, AGENTS)
        for name in AGENTS:
            path = ROOT / "agents" / f"{name}.md"
            self.assertNotIn(b"\r", path.read_bytes(), "G42: агент із CRLF стає невидимим")
            meta = frontmatter(path)
            self.assertEqual(meta.get("name", "").strip(), name)
            self.assertTrue(meta.get("description", "").strip(), name)
            self.assertTrue(meta.get("tools", "").strip(), name)
            for ignored in ("hooks", "mcpServers", "permissionMode"):
                self.assertNotIn(ignored, meta, f"{name}: плагін ігнорує {ignored}")

    def test_writers_are_isolated_and_readers_cannot_write(self):
        for name in ("builder", "tester", "debugger", "maintainer"):
            self.assertEqual(frontmatter(ROOT / "agents" / f"{name}.md").get("isolation", "").strip(), "worktree", name)
        for name in ("reviewer", "security", "release-gate", "auditor", "researcher", "brain"):
            tools = frontmatter(ROOT / "agents" / f"{name}.md")["tools"]
            self.assertNotRegex(tools, r"\b(Write|Edit)\b", name)


class TestCommands(unittest.TestCase):
    def subcommands(self):
        parser = build_parser()
        action = next(a for a in parser._actions if hasattr(a, "choices") and a.choices)
        return set(action.choices)

    def test_all_present(self):
        self.assertEqual({p.stem for p in (ROOT / "commands").glob("*.md")}, COMMANDS)

    def test_engine_calls_refer_to_real_subcommands(self):
        known = self.subcommands()
        pattern = re.compile(r"-m keel ([a-z][a-z\-]*)")
        for folder in ("commands", "agents", "skills"):
            for path in (ROOT / folder).rglob("*.md"):
                for sub in pattern.findall(path.read_text(encoding="utf-8")):
                    self.assertIn(sub, known, f"{path.name}: {sub}")

    def test_commands_do_not_preauthorize_apply(self):
        """Застосування планувальника, налаштувань і видалення йде через запит дозволу."""
        for path in (ROOT / "commands").glob("*.md"):
            allowed = frontmatter(path).get("allowed-tools", "")
            self.assertNotIn("--apply", allowed, path.name)
            self.assertNotRegex(allowed, r"Bash\(\*\)|Bash\(sh \*\)", path.name)


class TestManifest(unittest.TestCase):
    def test_hooks_cover_every_writer(self):
        hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))["hooks"]
        matcher = hooks["PreToolUse"][0]["matcher"]
        for tool in ("Bash", "PowerShell", "Write", "Edit", "NotebookEdit"):
            self.assertIn(tool, matcher)
        self.assertIn("keel.guard", hooks["PreToolUse"][0]["hooks"][0]["command"])
        self.assertIn("keel.session", hooks["SessionStart"][0]["hooks"][0]["command"])

    def test_engine_uses_only_stdlib(self):
        import ast  # noqa: PLC0415
        import sys  # noqa: PLC0415
        for path in (ROOT / "engine" / "keel").rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    names = [node.module or ""]
                for name in names:
                    top = name.split(".")[0]
                    self.assertTrue(top in sys.stdlib_module_names or top == "keel", f"{path.name}: {name}")


if __name__ == "__main__":
    unittest.main()
