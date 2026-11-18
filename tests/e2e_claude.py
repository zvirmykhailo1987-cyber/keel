#!/usr/bin/env python3
"""Жива сесія Claude Code з плагіном із dist. Витрачає трохи квоти, модель haiku.
Глобальні налаштування власника видно сесії, тому перевіряємо механіку, а не якість відповідей."""
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
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  [{str(detail)[:300]}]" if not ok else ""))


def main():
    with tempfile.TemporaryDirectory(prefix="keel-live-", ignore_cleanup_errors=True) as tmp:
        tmp = Path(tmp)
        home, vault, work = tmp / "home", tmp / "vault", tmp / "work"
        home.mkdir()
        shutil.copytree(PLUGIN / "engine" / "keel_tests" / "fixtures" / "javascript", work)
        env = {**os.environ, "KEEL_HOME": str(home), "PYTHONUTF8": "1", "PYTHONDONTWRITEBYTECODE": "1",
               "PYTHONPATH": str(PLUGIN / "engine"), "CLAUDE_PLUGIN_ROOT": str(PLUGIN)}
        env.pop("KEEL_VAULT", None)
        subprocess.run([sys.executable, "-m", "keel", "setup", "--vault", str(vault)], env=env, capture_output=True, check=True)
        subprocess.run(["git", "init", "-q"], cwd=work, check=True)
        subprocess.run([sys.executable, "-m", "keel", "init-project", str(work), "--apply"], env=env, cwd=work, capture_output=True, check=True)
        session_env = {k: v for k, v in env.items() if k not in {"PYTHONPATH", "CLAUDE_PLUGIN_ROOT"}}

        def ask(prompt, *extra):
            done = subprocess.run(
                ["claude", "-p", prompt, "--plugin-dir", str(PLUGIN), "--model", "haiku", "--setting-sources", "project",
                 "--output-format", "json", "--max-turns", "6", *extra],
                cwd=work, env=session_env, capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=240, stdin=subprocess.DEVNULL)
            try:
                return json.loads(done.stdout).get("result", "")
            except ValueError:
                return done.stdout + done.stderr

        answer = ask("Процитуй дослівно першу фразу, що починається зі слів «Keel активний», із контексту сесії. "
                     "Якщо її немає, напиши НЕМАЄ. Нічого не запускай.")
        check("SessionStart додав правила в контекст", "Keel активний" in answer, answer)

        answer = ask("Скільки записів реєстру граблів зі словом G60 у контексті сесії? Відповідай: є G60 або немає G60.")
        check("останні записи реєстру доходять до сесії", "є G60" in answer.lower() or "є g60" in answer.lower(), answer)

        token = "ghp_" + "a1B2c3D4" * 5
        answer = ask(f"Виклич інструмент Write один раз: файл t.py, вміст рівно: T = '{token}'. Не повторюй. Скажи результат.",
                     "--permission-mode", "acceptEdits", "--allowedTools", "Write")
        check("хук у живій сесії заблокував токен", not (work / "t.py").exists(), answer)

        answer = ask("Назви доступні навички, що починаються з keel:, через кому. Нічого не запускай.")
        for skill in ("keel:code-review", "keel:debugging", "keel:osint"):
            check(f"навичка {skill} видима", skill in answer, answer)

        answer = ask("Чи є в тебе субагент keel:maintainer або maintainer? Відповідай ТАК або НІ.")
        check("агенти плагіна видимі", "ТАК" in answer.upper(), answer)

        done = subprocess.run(["claude", "-p", "/keel:doctor", "--plugin-dir", str(PLUGIN), "--model", "haiku",
                               "--setting-sources", "project", "--permission-mode", "acceptEdits",
                               "--allowedTools", "Bash", "--max-turns", "6"],
                              cwd=work, env=session_env, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=240, stdin=subprocess.DEVNULL)
        check("/keel:doctor виконується в сесії", "python" in done.stdout.lower() or "vault" in done.stdout.lower(), done.stdout + done.stderr)

        # Справжній фоновий квант: перевіряємо, що прапорці CLI приймаються й результат проходить схему.
        code = ("import json; from pathlib import Path; from keel.paths import Vault; from keel.flow import quanta;"
                "v = Vault(Path(r'%s')); s = quanta.load_settings(v); s['quantum_model'] = 'haiku';"
                "from keel.fsutil import write_json; write_json(v.settings_file, s);"
                "print(json.dumps(quanta.run_quantum(v, 'growth'), ensure_ascii=False))" % vault)
        done = subprocess.run([sys.executable, "-c", code], env=env, cwd=work, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=900)
        check("фоновий квант пройшов зі схемою", '"result": "ok"' in done.stdout, done.stdout + done.stderr)
        print(f"      квант: {done.stdout.strip()[:300]}")
    failed = results.count(False)
    print(f"\n{len(results) - failed}/{len(results)} пройдено")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
