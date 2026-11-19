#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Mykhailo Zvir

"""Чи викликається навичка на своїх задачах і чи мовчить на чужих. Витрачає квоту, модель haiku.
Запуск: python tests/eval_triggers.py [кейсів_на_навичку]
Міряє лише тригер, а не якість результату. Сторонні навички власника можуть конкурувати,
тому результат тут це нижня оцінка, а не точна цифра для чистої установки."""
import json
import os
import random
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "dist" / "keel-marketplace" / "plugins" / "keel"
PER_SKILL = int(sys.argv[1]) if len(sys.argv) > 1 else 3


def used_skills(prompt, cwd, env):
    done = subprocess.run(
        ["claude", "-p", prompt + "\n\n(Це перевірка маршрутизації: якщо підходить навичка, виклич її одразу, далі нічого не роби.)",
         "--plugin-dir", str(PLUGIN), "--model", "haiku", "--setting-sources", "project", "--output-format", "stream-json",
         "--verbose", "--max-turns", "2", "--allowedTools", "Skill"],
        cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=240,
        stdin=subprocess.DEVNULL)
    found = set()
    for line in done.stdout.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        content = ((event.get("message") if isinstance(event, dict) else None) or {})
        content = content.get("content") if isinstance(content, dict) else None
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use" and block.get("name") == "Skill":
                    found.add(str(block.get("input", {}).get("skill", "")))
    return found


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    random.seed(7)
    cases = []
    for path in sorted((PLUGIN / "skills").glob("*/evals/evals.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        positive = [c for c in data["cases"] if c["should_trigger"]]
        negative = [c for c in data["cases"] if not c["should_trigger"]]
        chosen = random.sample(positive, min(PER_SKILL - 1, len(positive))) + random.sample(negative, min(1, len(negative)))
        cases += [(data["skill"], c) for c in chosen]
    with tempfile.TemporaryDirectory(prefix="keel-eval-", ignore_cleanup_errors=True) as tmp:
        env = {**os.environ, "KEEL_HOME": tmp, "KEEL_VAULT": str(Path(tmp) / "v")}

        def run(item):
            skill, case = item
            try:
                used = used_skills(case["prompt"], tmp, env)
            except subprocess.TimeoutExpired:
                return skill, case, None
            return skill, case, used

        with ThreadPoolExecutor(4) as pool:
            outcomes = list(pool.map(run, cases))
    tp = fn = tn = fp = errors = foreign = other_keel = silent = 0
    for skill, case, used in outcomes:
        name = f"keel:{skill}"
        if used is None:
            errors += 1
            continue
        hit = name in used
        if case["should_trigger"]:
            tp += hit
            fn += not hit
            if not hit:
                keel_used = [u for u in used if u.startswith("keel:")]
                other_keel += bool(keel_used)
                foreign += bool(used) and not keel_used  # конкурує навичка власника: у друга її немає
                silent += not used
        else:
            tn += not hit
            fp += hit
        if hit != case["should_trigger"]:
            print(f"ПРОМАХ {skill} (очікували {case['should_trigger']}, викликано {sorted(used)}): {case['prompt'][:90]}")
    total = tp + fn
    print(f"\nСвої задачі: {tp}/{total} викликано. Чужі задачі: {tn}/{tn + fp} не викликано. Таймаутів: {errors}. Кейсів: {len(cases)}")
    print(f"Промахи своїх: сусідня навичка Keel {other_keel}, чужа навичка цього комп'ютера {foreign}, без виклику {silent}")
    clean = total - foreign
    print(f"Без конкуренції чужих навичок: {tp}/{clean} точно в ціль, {tp + other_keel}/{clean} хоч якась навичка Keel")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
