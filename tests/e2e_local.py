#!/usr/bin/env python3
"""Наскрізний прогін на зібраному дистрибутиві. Без LLM, мережа жива (OSV, реєстри).
Запуск: python tests/e2e_local.py [--real-schedule]
--real-schedule реєструє справжнє завдання Windows/launchd і одразу його знімає."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "dist" / "keel-marketplace" / "plugins" / "keel"
results = []


def check(name, ok, detail=""):
    results.append(bool(ok))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  [{str(detail)[:200]}]" if detail and not ok else ""))


def main():
    real_schedule = "--real-schedule" in sys.argv
    with tempfile.TemporaryDirectory(prefix="keel-e2e-", ignore_cleanup_errors=True) as tmp:
        tmp = Path(tmp)
        home, vault = tmp / "home", tmp / "vault"
        home.mkdir()
        env = {**os.environ, "KEEL_HOME": str(home), "PYTHONUTF8": "1", "PYTHONDONTWRITEBYTECODE": "1",
               "CLAUDE_PLUGIN_ROOT": str(PLUGIN), "PYTHONPATH": str(PLUGIN / "engine")}
        env.pop("KEEL_VAULT", None)

        def keel(*args, stdin=None, cwd=None):
            done = subprocess.run([sys.executable, "-m", "keel", *args], env=env, cwd=cwd or tmp, input=stdin,
                                  capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
            try:
                return done.returncode, json.loads(done.stdout)
            except ValueError:
                return done.returncode, done.stdout + done.stderr

        repo = tmp / "web"
        shutil.copytree(PLUGIN / "engine" / "keel_tests" / "fixtures" / "javascript", repo)

        def git(*args):
            return subprocess.run(["git", "-c", "user.email=t@t.test", "-c", "user.name=t", *args], cwd=repo,
                                  capture_output=True, text=True, encoding="utf-8", errors="replace", env=env)

        git("init", "-q", "-b", "main")
        git("add", ".")
        git("commit", "-qm", "start")

        code, out = keel("setup", "--vault", str(vault))
        check("setup створює vault", code == 0 and (vault / ".keel" / "tick.py").exists(), out)
        code, out = keel("doctor")
        names = {i["name"]: i["status"] for i in out["items"]} if isinstance(out, dict) else {}
        check("doctor працює", bool(names), out)
        check("doctor бачить вимкнений планувальник", names.get("планувальник") == "warn", names)

        code, out = keel("init-project", str(repo))
        check("init-project без --apply нічого не пише",
              not (repo / ".keel").exists() and isinstance(out, dict) and "javascript" in out["stacks"], out)
        code, out = keel("init-project", str(repo), "--apply")
        check("init-project --apply", (repo / ".keel" / "project.toml").exists()
              and (repo / ".git" / "hooks" / "pre-commit").exists(), out)
        toml = (repo / ".keel" / "project.toml").read_text(encoding="utf-8")
        check("автопілот вимкнено", "enabled = false" in toml)

        code, out = keel("radar", "--force")
        check("radar знаходить вразливість наживо", isinstance(out, dict) and out["new"] > 0, out)
        check("джерела відповіли", isinstance(out, dict) and not out["source_errors"], out)
        report = (vault / ".keel" / "reports" / "radar-latest.md").read_text(encoding="utf-8")
        check("звіт називає lodash", "lodash" in report)

        code, out = keel("decide", "--list")
        check("є картка рішення", isinstance(out, dict) and len(out["today"]) >= 1, out)
        check("HTML вікна рішень існує", (vault / ".keel" / "reports" / "decisions.html").exists())
        before = git("rev-parse", "HEAD").stdout

        tier3 = json.dumps({"action": "push_main", "params": {"project": "web"}, "why": "тест", "confidence": 1.0})
        code, out = keel("propose", stdin=tier3)
        card = out[0].get("card") if isinstance(out, list) else None
        check("Tier 3 стає карткою", card is not None, out)
        code, out = keel("decide", card, "yes")
        check("схвалений Tier 3 не виконується, лише команда",
              isinstance(out, list) and out[0]["outcome"]["result"] == "human", out)
        check("HEAD репозиторію не змінився", git("rev-parse", "HEAD").stdout == before)

        note = json.dumps({"action": "add_lesson", "confidence": 0.9,
                           "params": {"title": "Урок наскрізного тесту", "body": "Текст", "evidence": "e2e"}})
        code, out = keel("propose", stdin=note)
        event = out[0].get("event") if isinstance(out, list) else None
        check("Tier 1 виконується й комітить у vault", event is not None, out)
        path = vault / out[0]["path"]
        code, undo = keel("undo", event)
        check("undo повертає назад", code == 0 and not path.exists(), undo)

        (repo / "leak.py").write_text('API_TOKEN = "' + "s3cr3tValue_ABC123xyz789" + '"\n', encoding="utf-8")
        git("add", "leak.py")
        check("pre-commit зупиняє секрет", git("commit", "-qm", "leak").returncode != 0)
        git("reset", "-q", "--hard", "HEAD")
        (repo / "leak.py").unlink(missing_ok=True)

        token = "ghp_" + "a1B2c3D4" * 5
        payload = {"tool_name": "Write", "cwd": str(repo),
                   "tool_input": {"file_path": str(repo / "a.py"), "content": f"t = '{token}'"}}
        run_sh = [shutil.which("sh") or "sh", str(PLUGIN / "hooks" / "run.sh"), "-m", "keel.guard"]
        blocked = subprocess.run(run_sh, input=json.dumps(payload), env=env, capture_output=True, text=True, encoding="utf-8")
        check("хук через run.sh повертає 2", blocked.returncode == 2, blocked.stderr)
        run_sh[3] = "keel.session"
        context = subprocess.run(run_sh, env=env, capture_output=True, text=True, encoding="utf-8")
        data = json.loads(context.stdout)["hookSpecificOutput"]["additionalContext"]
        check("SessionStart дає контекст у ліміті", "Tier 3" in data and len(data) <= 10000, len(data))
        print(f"      розмір контексту сесії: {len(data)} символів")

        if shutil.which("npm"):
            (repo / ".keel" / "project.toml").write_text(toml.replace("enabled = false", "enabled = true"),
                                                         encoding="utf-8", newline="\n")
            # Фікстура містить вигаданий @scope/lib, тому для справжнього npm беремо чистий маніфест.
            (repo / "package.json").write_text('{"name":"web","version":"1.0.0","dependencies":{"ms":"2.1.2"}}\n', encoding="utf-8", newline="\n")
            (repo / "package-lock.json").unlink()
            subprocess.run([shutil.which("npm"), "install", "--package-lock-only", "--ignore-scripts"], cwd=repo,
                           capture_output=True, check=True)
            git("add", ".")
            git("commit", "-qm", "keel", "--no-verify")
            bump = json.dumps({"action": "dep_patch_branch", "confidence": 1.0, "why": "e2e", "params": {
                "project": "web", "ecosystem": "npm", "package": "ms", "from_version": "2.1.2",
                "to_version": "2.1.3"}})
            code, out = keel("propose", stdin=bump)
            branch = out[0].get("branch") if isinstance(out, list) else None
            check("Tier 2: справжній npm створює гілку keel/*", bool(branch), out)
            check("поточна гілка лишилась main", git("branch", "--show-current").stdout.strip() == "main")
            if branch:
                lock = git("show", f"{branch}:package-lock.json").stdout
                check("у гілці ms оновлено", '"version": "2.1.3"' in lock, lock[:300])
                check("робоче дерево не змінилось",
                      "2.1.3" not in (repo / "package-lock.json").read_text(encoding="utf-8"))
        else:
            print("SKIP  npm не знайдено")

        code, out = keel("tick")
        check("tick працює", isinstance(out, dict) and out.get("background") == "off", out)

        if real_schedule:
            code, out = keel("autopilot", "schedule", "--apply")
            check("справжнє завдання зареєстровано", isinstance(out, dict) and out.get("registered") is True, out)
            shim = subprocess.run([sys.executable, str(vault / ".keel" / "tick.py")], capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", timeout=600, env={**env, "KEEL_FAKE_NOW": ""})
            last = json.loads((vault / ".keel" / "state" / "tick-last.json").read_text(encoding="utf-8"))
            check("shim запускає поточну версію", shim.returncode == 0 and not last["error"], last)
            code, out = keel("autopilot", "status")
            check("verify бачить живий tick", isinstance(out, dict) and out["schedule"]["ok"], out)
            code, out = keel("uninstall", "--apply")
            check("uninstall зняв завдання", isinstance(out, dict) and out["scheduler_removed"], out)
            code, out = keel("autopilot", "status")
            check("завдання справді зникло", isinstance(out, dict) and out["schedule"]["registered"] is False, out)
        else:
            keel("uninstall", "--apply")
        check("vault лишився", (vault / "README.md").exists())
    failed = results.count(False)
    print(f"\n{len(results) - failed}/{len(results)} пройдено")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
