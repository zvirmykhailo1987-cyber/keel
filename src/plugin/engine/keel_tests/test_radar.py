"""Radar офлайн: lockfile кожного стеку, детект, чесність при збоях джерел."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from keel import fetch as net
from keel.fsutil import write_json
from keel.paths import Vault
from keel.radar import engine, sources, versions
from keel.radar.lockfiles import Dep, parse_project
from keel.stacks import detect, load_stacks

FIX = Path(__file__).parent / "fixtures"
PLUGIN = Path(__file__).resolve().parents[2]


def names(project):
    return {(d.ecosystem, d.name, d.version) for d in parse_project(FIX / project).deps}


class TestLockfiles(unittest.TestCase):
    def test_each_format(self):
        cases = {
            "python": {("PyPI", "requests", "2.19.0"), ("PyPI", "flask", "2.0.0"), ("PyPI", "pyyaml", "5.3")},
            "javascript": {("npm", "lodash", "4.17.20"), ("npm", "@scope/lib", "1.2.3"), ("npm", "lodash", "3.10.1")},
            "pnpm": {("npm", "lodash", "4.17.20"), ("npm", "@babel/core", "7.23.0")},
            "yarn": {("npm", "lodash", "4.17.20"), ("npm", "@babel/core", "7.23.0")},
            "go": {("Go", "golang.org/x/text", "v0.3.0"), ("Go", "github.com/gin-gonic/gin", "v1.6.0")},
            "rust": {("crates.io", "time", "0.1.43")},
            "java": {("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")},
            "kotlin": {("Maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.8")},
            "dotnet": {("NuGet", "Newtonsoft.Json", "12.0.1")},
            "php": {("Packagist", "guzzlehttp/guzzle", "7.4.0")},
            "ruby": {("RubyGems", "rack", "2.0.1"), ("RubyGems", "nokogiri", "1.10.0")},
            "swift": {("SwiftURL", "github.com/vapor/vapor", "4.0.0")},
        }
        for project, expected in cases.items():
            with self.subTest(project):
                self.assertLessEqual(expected, names(project))

    def test_unpinned_requirement_is_not_invented(self):
        self.assertFalse([n for n in names("python") if n[1] == "uvicorn"])

    def test_pom_property_version_skipped_and_marked_incomplete(self):
        result = parse_project(FIX / "java")
        self.assertEqual(len(result.deps), 1)
        self.assertTrue(result.incomplete)

    def test_direct_flag(self):
        deps = {d.name: d for d in parse_project(FIX / "javascript").deps if d.version != "3.10.1"}
        self.assertTrue(deps["lodash"].direct)
        self.assertFalse(deps["@scope/lib"].direct)

    def test_broken_file_is_incomplete_not_empty(self):
        """G15: зламаний lockfile не дорівнює «залежностей немає»."""
        result = parse_project(FIX / "broken")
        self.assertEqual(result.deps, [])
        self.assertTrue(any("не вдалося" in i["reason"] for i in result.incomplete))

    def test_cpp_without_manifest_is_incomplete(self):
        self.assertTrue(parse_project(FIX / "cpp").incomplete)

    def test_skips_vendored_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            nested = Path(tmp) / "node_modules" / "x"
            nested.mkdir(parents=True)
            (nested / "requirements.txt").write_text("evil==1.0\n", encoding="utf-8")
            self.assertEqual(parse_project(Path(tmp)).deps, [])


class TestDetect(unittest.TestCase):
    def test_every_profile_detected_on_its_fixture(self):
        stacks = load_stacks(PLUGIN / "data" / "stacks")
        self.assertGreaterEqual(len(stacks), 11)
        for stack in stacks:
            with self.subTest(stack.id):
                self.assertIn(stack.id, [s.id for s in detect(FIX / stack.id, stacks)])

    def test_profiles_have_required_fields(self):
        for stack in load_stacks(PLUGIN / "data" / "stacks"):
            with self.subTest(stack.id):
                self.assertTrue(stack.commands.get("test"), "немає команди тестів")
                self.assertTrue(stack.pitfalls)
                self.assertTrue(stack.verified)


class TestVersions(unittest.TestCase):
    def test_gap(self):
        self.assertEqual(versions.gap("1.2.3", "2.0.0"), "major")
        self.assertEqual(versions.gap("1.2.3", "1.3.0"), "minor")
        self.assertEqual(versions.gap("v1.2.3", "v1.2.4"), "patch")
        self.assertEqual(versions.gap("1.2", "1.2.0"), "none")
        self.assertEqual(versions.gap("2.0.0", "1.0.0"), "none")
        self.assertIsNone(versions.gap("abc", "1.0.0"))

    def test_newest_ignores_prerelease_and_sorts_numerically(self):
        self.assertEqual(versions.newest(["1.9.0", "1.10.0", "2.0.0-beta1", "2.0.0rc1"]), "1.10.0")


class FakeNet:
    """Відповідає на запити за простими правилами й рахує, що запитували."""

    def __init__(self, osv_fail=False):
        self.osv_fail, self.calls = osv_fail, []

    def __call__(self, url, method, data, headers, timeout):
        self.calls.append(url)
        if "querybatch" in url:
            if self.osv_fail:
                raise net.FetchError("net", url, "немає мережі")
            queries = json.loads(data)["queries"]
            results = [{"vulns": [{"id": "GHSA-test"}]} if q["package"]["name"] == "lodash" else {} for q in queries]
            return net.Response(url, 200, json.dumps({"results": results}).encode())
        if "/v1/vulns/" in url:
            return net.Response(url, 200, json.dumps({
                "summary": "Тест", "database_specific": {"severity": "HIGH"},
                "affected": [{"package": {"name": "lodash", "ecosystem": "npm"},
                              "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]}).encode())
        if "registry.npmjs.org" in url:
            return net.Response(url, 200, b'{"version": "4.17.21"}')
        if "endoflife.date" in url:
            return net.Response(url, 200, json.dumps([{"cycle": "20", "eol": "2030-01-01"},
                                                      {"cycle": "16", "eol": "2023-09-11"}]).encode())
        if url.endswith("releases.atom"):
            return net.Response(url, 200, b'<feed xmlns="http://www.w3.org/2005/Atom"></feed>')
        raise net.FetchError("http", url, "404")


class RadarCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.vault = Vault(Path(tmp.name) / "v")
        self.vault.init()
        write_json(self.vault.projects_file, {"web": str(FIX / "javascript")})
        self.stacks = load_stacks(PLUGIN / "data" / "stacks")
        self.addCleanup(net.set_transport, None)

    def run_radar(self, network, force=True):
        net.set_transport(network)
        return engine.run(self.vault, force=force, stacks=self.stacks)


class TestRadarRun(RadarCase):
    def test_finds_vuln_outdated_and_eol(self):
        result = self.run_radar(FakeNet())
        kinds = {f["kind"] for f in result["new"]}
        self.assertEqual(kinds, {"vuln", "outdated", "eol"})
        vuln = next(f for f in result["new"] if f["kind"] == "vuln")
        self.assertEqual(vuln["data"]["fixed"], ["4.17.21"])
        self.assertIn("osv.dev", vuln["url"])

    def test_second_run_reports_nothing_new(self):
        self.run_radar(FakeNet())
        self.assertEqual(self.run_radar(FakeNet())["new"], [])

    def test_osv_outage_is_reported_and_keeps_known_vuln(self):
        """Головна чесність: збій джерела не «лікує» вразливість і не виглядає чистотою."""
        self.run_radar(FakeNet())
        result = self.run_radar(FakeNet(osv_fail=True))
        self.assertTrue(any("НЕ перевірено" in u for u in result["unchecked"]))
        state = json.loads((self.vault.state / "radar.json").read_text(encoding="utf-8"))
        self.assertIn("vuln", {f["kind"] for f in state["findings"].values()})
        report = (self.vault.reports / "radar-latest.md").read_text(encoding="utf-8")
        self.assertIn("Перевірено не все", report)

    def test_outage_on_first_run_never_says_clean(self):
        write_json(self.vault.projects_file, {"web": str(FIX / "pnpm")})
        result = self.run_radar(FakeNet(osv_fail=True))
        report = (self.vault.reports / "radar-latest.md").read_text(encoding="utf-8")
        self.assertTrue(result["unchecked"])
        self.assertNotIn("Знахідок немає.\n", report)

    def test_fixed_vuln_disappears_when_really_checked(self):
        self.run_radar(FakeNet())
        clean = FakeNet()
        original = clean.__call__

        def no_vulns(url, method, data, headers, timeout):
            if "querybatch" in url:
                return net.Response(url, 200, b'{"results": [{}, {}, {}]}')
            return original(url, method, data, headers, timeout)

        self.run_radar(no_vulns)
        state = json.loads((self.vault.state / "radar.json").read_text(encoding="utf-8"))
        self.assertNotIn("vuln", {f["kind"] for f in state["findings"].values()})

    def test_cadence_skips_osv_until_due(self):
        with mock.patch.dict(os.environ, {"KEEL_FAKE_NOW": "2026-01-01T00:00:00Z"}):
            self.run_radar(FakeNet(), force=False)
        later = FakeNet()
        with mock.patch.dict(os.environ, {"KEEL_FAKE_NOW": "2026-01-01T01:00:00Z"}):
            self.run_radar(later, force=False)
        self.assertFalse([u for u in later.calls if "querybatch" in u])
        due = FakeNet()
        with mock.patch.dict(os.environ, {"KEEL_FAKE_NOW": "2026-01-01T07:00:00Z"}):
            self.run_radar(due, force=False)
        self.assertTrue([u for u in due.calls if "querybatch" in u])

    def test_feed_first_run_is_silent_then_reports_new(self):
        feed = (b'<feed xmlns="http://www.w3.org/2005/Atom"><entry><id>%s</id><title>v%s</title>'
                b'<link href="https://x.test/r"/></entry></feed>')
        state = engine.RadarState(self.vault)
        outcome = engine.ScanOutcome()
        net.set_transport(lambda u, m, d, h, t: net.Response(u, 200, feed % (b"1", b"1")))
        engine.scan_feeds(["a/b"], state, outcome, self.vault.cache)
        self.assertEqual(outcome.findings, [])
        net.set_transport(lambda u, m, d, h, t: net.Response(u, 200, feed % (b"2", b"2")))
        engine.scan_feeds(["a/b"], state, outcome, self.vault.cache)
        self.assertEqual(len(outcome.findings), 1)

    def test_missing_project_dir_is_visible(self):
        write_json(self.vault.projects_file, {"gone": str(FIX / "немає")})
        self.assertTrue(any("не знайдено" in u for u in self.run_radar(FakeNet())["unchecked"]))


class TestScoring(unittest.TestCase):
    def test_unknown_severity_above_low(self):
        self.assertGreater(engine.vuln_score("UNKNOWN", False), engine.vuln_score("LOW", False))

    def test_direct_above_transitive(self):
        self.assertGreater(engine.vuln_score("HIGH", True), engine.vuln_score("HIGH", None))


class TestSources(unittest.TestCase):
    def test_go_capitals_escaped(self):
        seen = []

        def transport(url, *_):
            seen.append(url)
            return net.Response(url, 200, b'{"Version": "v1.0.0"}')

        net.set_transport(transport)
        self.addCleanup(net.set_transport, None)
        sources.latest_version(Dep("Go", "github.com/Azure/x", "v0.1.0", "go.mod"))
        self.assertIn("!azure", seen[0])

    def test_unsupported_ecosystem_returns_none(self):
        self.assertIsNone(sources.latest_version(Dep("SwiftURL", "u", "1", "s")))


if __name__ == "__main__":
    unittest.main()
