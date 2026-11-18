"""Журнал, мережа, файли, час."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from keel import fetch as net
from keel.fsutil import FileLock, LockBusy, write_text
from keel.journal import Journal, JournalCorrupt


class Tmp(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)


class TestFiles(Tmp):
    def test_write_is_lf_and_utf8(self):
        target = self.tmp / "a" / "b.txt"
        write_text(target, "рядок\nдругий\n")
        self.assertEqual(target.read_bytes(), "рядок\nдругий\n".encode("utf-8"))

    def test_lock_busy_then_stale(self):
        path = self.tmp / "l"
        with FileLock(path):
            with self.assertRaises(LockBusy):
                with FileLock(path, wait_seconds=0.1):
                    pass
        write_text(path, "")
        old = path.stat().st_mtime - 5000
        os.utime(path, (old, old))
        with FileLock(path, stale_seconds=10, wait_seconds=0.1):
            pass


class TestJournal(Tmp):
    def journal(self):
        return Journal(self.tmp / "j", self.tmp / "s")

    def test_append_splits_by_month(self):
        j = self.journal()
        with mock.patch.dict(os.environ, {"KEEL_FAKE_NOW": "2026-01-31T23:00:00Z"}):
            j.append("a", {"n": 1})
        with mock.patch.dict(os.environ, {"KEEL_FAKE_NOW": "2026-02-01T01:00:00Z"}):
            j.append("b")
        self.assertEqual([p.name for p in j.segments()], ["2026-01.jsonl", "2026-02.jsonl"])
        self.assertEqual([e["kind"] for e in j.events()], ["a", "b"])

    def test_fold_continues_without_rereading(self):
        j = self.journal()
        j.append("x")
        j.append("x")
        calls = []

        def reducer(state, event):
            calls.append(event["id"])
            return state + 1

        self.assertEqual(j.fold("n", reducer, 0), 2)
        j.append("x")
        self.assertEqual(j.fold("n", reducer, 0), 3)
        self.assertEqual(len(calls), 3)

    def test_fold_version_change_recomputes(self):
        j = self.journal()
        j.append("x")
        j.fold("n", lambda s, e: s + 1, 0, version=1)
        self.assertEqual(j.fold("n", lambda s, e: s + 10, 0, version=2), 10)

    def test_torn_tail_is_ignored_but_middle_corruption_raises(self):
        j = self.journal()
        j.append("x")
        segment = j.segments()[0]
        with segment.open("a", encoding="utf-8") as handle:
            handle.write('{"kind": "обірв')
        self.assertEqual(len(list(j.events())), 1)
        with segment.open("a", encoding="utf-8") as handle:
            handle.write("\n")
        with self.assertRaises(JournalCorrupt):
            list(j.events())


class TestFetch(Tmp):
    def test_rejects_http_and_private_addresses(self):
        with self.assertRaises(net.FetchError) as caught:
            net.check_url("http://example.com/")
        self.assertEqual(caught.exception.kind, "blocked")
        for address in ("127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "192.168.1.1"):
            with self.assertRaises(net.FetchError):
                net.check_url("https://x.test/", resolver=lambda _h, a=address: [a])
        net.check_url("https://x.test/", resolver=lambda _h: ["93.184.216.34"])

    def test_tls_verification_cannot_be_off_in_source(self):
        """Вимкнення перевірки TLS не має існувати в рушії взагалі."""
        engine = Path(net.__file__).parent
        banned = "CERT_" + "NONE"
        hostname = "check_hostname = " + "False"
        for path in engine.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn(banned, text, path.name)
            self.assertNotIn(hostname, text, path.name)

    def test_etag_cache_returns_body_on_304(self):
        seen = []

        def transport(url, method, data, headers, timeout):
            seen.append(headers.get("If-None-Match"))
            if len(seen) == 1:
                return net.Response(url, 200, b"body", {"ETag": '"v1"'})
            return net.Response(url, 304, b"")

        net.set_transport(transport)
        self.addCleanup(net.set_transport, None)
        first = net.fetch("https://x.test/a", cache_dir=self.tmp)
        second = net.fetch("https://x.test/a", cache_dir=self.tmp)
        self.assertEqual(first.body, b"body")
        self.assertEqual(second.body, b"body")
        self.assertTrue(second.from_cache)
        self.assertEqual(seen, [None, '"v1"'])

    def test_replay_transport(self):
        (self.tmp / "manifest.json").write_text(json.dumps(
            {"GET https://x.test/a": "a.json", "GET https://x.test/gone": 404}), encoding="utf-8")
        (self.tmp / "a.json").write_text('{"ok": true}', encoding="utf-8")
        net.set_transport(net.ReplayTransport(self.tmp))
        self.addCleanup(net.set_transport, None)
        self.assertEqual(net.fetch("https://x.test/a").json(), {"ok": True})
        for url in ("https://x.test/gone", "https://x.test/missing"):
            with self.assertRaises(net.FetchError):
                net.fetch(url)


if __name__ == "__main__":
    unittest.main()
