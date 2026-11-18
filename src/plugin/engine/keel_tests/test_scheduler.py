"""Планувальник без справжньої реєстрації: зовнішні команди підмінені."""
import os
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

from keel.fsutil import write_json
from keel.paths import Vault
from keel.scheduler import CRON_BEGIN, Scheduler, _strip_block, install_shim


class FakeRunner:
    def __init__(self):
        self.calls, self.crontab, self.fail = [], "", None

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if self.fail and self.fail in args:
            return subprocess.CompletedProcess(args, 1, "", "відмовлено")
        if args[:2] == ["crontab", "-l"]:
            return subprocess.CompletedProcess(args, 0 if self.crontab else 1, self.crontab, "")
        if args[:2] == ["crontab", "-"]:
            self.crontab = kwargs["input"]
        return subprocess.CompletedProcess(args, 0, "", "")


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.vault = Vault(self.tmp / "v")
        self.vault.init()
        patcher = mock.patch.dict(os.environ, {"KEEL_HOME": str(self.tmp)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.runner = FakeRunner()

    def make(self, system):
        return Scheduler(self.vault, system, self.runner, python="/py dir/python")


class TestPlans(Base):
    def test_windows_xml_catches_up_after_sleep(self):
        root = ET.fromstring(self.make("Windows").plan().artifact.encode("utf-16"))
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        self.assertEqual(root.find(".//t:StartWhenAvailable", ns).text, "true")
        self.assertEqual(root.find(".//t:RunLevel", ns).text, "LeastPrivilege")
        self.assertIn("tick.py", root.find(".//t:Arguments", ns).text)

    def test_plist_valid(self):
        root = ET.fromstring(self.make("Darwin").plan().artifact)
        self.assertEqual(root.tag, "plist")

    def test_unknown_system_refuses(self):
        with self.assertRaises(RuntimeError):
            self.make("Plan9").plan()


class TestCron(Base):
    def test_apply_keeps_foreign_lines_and_is_idempotent(self):
        self.runner.crontab = "0 1 * * * backup\n"
        sched = self.make("Linux")
        sched.apply()
        sched.apply()
        self.assertEqual(self.runner.crontab.count(CRON_BEGIN), 1)
        self.assertIn("backup", self.runner.crontab)
        sched.remove()
        self.assertEqual(self.runner.crontab, "0 1 * * * backup\n")

    def test_strip_on_empty(self):
        self.assertEqual(_strip_block(""), "")


class TestVerify(Base):
    def test_registered_but_never_ran_is_not_ok(self):
        """G11: зареєстрована, але мертва автоматизація не має виглядати здоровою."""
        self.runner.crontab = CRON_BEGIN + "\n"
        report = self.make("Linux").verify()
        self.assertFalse(report["ok"])
        self.assertIn("жодного", report["problem"])

    def test_fresh_run_ok_and_stale_not(self):
        self.runner.crontab = CRON_BEGIN + "\n"
        write_json(self.vault.state / "tick-last.json", {"ts": "2026-01-01T00:00:00Z", "error": None})
        with mock.patch.dict(os.environ, {"KEEL_FAKE_NOW": "2026-01-01T02:00:00Z"}):
            self.assertTrue(self.make("Linux").verify()["ok"])
        with mock.patch.dict(os.environ, {"KEEL_FAKE_NOW": "2026-01-03T00:00:00Z"}):
            self.assertFalse(self.make("Linux").verify()["ok"])

    def test_failed_run_is_not_ok(self):
        self.runner.crontab = CRON_BEGIN + "\n"
        write_json(self.vault.state / "tick-last.json", {"ts": "2026-01-01T00:00:00Z", "error": "збій"})
        with mock.patch.dict(os.environ, {"KEEL_FAKE_NOW": "2026-01-01T01:00:00Z"}):
            self.assertIn("збій", self.make("Linux").verify()["problem"])


class TestShim(Base):
    def test_shim_records_error_when_plugin_is_gone(self):
        """G50: збій до старту рушія теж має лишити слід, інакше панель брешe."""
        install_shim(self.vault)
        write_json(self.vault.current_file, {"plugin_root": str(self.tmp / "немає")})
        done = subprocess.run([sys.executable, str(self.vault.tick_shim)], capture_output=True)
        self.assertEqual(done.returncode, 1)
        last = (self.vault.state / "tick-last.json").read_text(encoding="utf-8")
        self.assertIn("немає рушія", last)


if __name__ == "__main__":
    unittest.main()
