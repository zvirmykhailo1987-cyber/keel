"""Підключення репозиторію. Спершу план і diff, зміни лише після явного --apply.
Плагін не може задавати permissions (документація), тому їх пише ця команда за згодою людини."""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from .fsutil import read_json, write_json, write_text
from .paths import Vault
from .stacks import detect

DENY = [
    "Read(./.env)", "Read(./.env.*)", "Read(**/*.pem)", "Read(**/*.key)", "Read(**/id_rsa)", "Read(**/id_ed25519)",
    "Read(**/.aws/credentials)", "Bash(git push --force*)", "Bash(git push -f*)", "Bash(git push origin main*)",
    "Bash(git push origin master*)", "Bash(git reset --hard*)", "Bash(rm -rf /*)", "Bash(curl * | sh*)", "Bash(curl * | bash*)",
    "Bash(sudo *)", "Bash(git diff*--output*)", "Bash(git log*--output*)", "Bash(git show*--output*)",
]
# Команди читання. Широкі `python *`, `curl *`, `cat *` свідомо не додаються: через них обходиться
# кожне правило deny. `git branch*` теж ні, бо пропускав би `git branch -D`. Запис файлу через
# `git diff|log|show --output` закриває окреме правило deny.
BASE_ALLOW = ["Bash(git status*)", "Bash(git diff*)", "Bash(git log*)", "Bash(git show*)", "Bash(git branch)",
              "Bash(git branch --list*)", "Bash(git branch --show-current*)"]
_HOOK_BODY = """for c in python3 python "py -3"; do
  if $c -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then
    root=$($c - <<'PY'
import json, os, pathlib
home = pathlib.Path(os.environ.get("KEEL_HOME") or pathlib.Path.home())
try:
    vault = json.loads((home / ".keel/config.json").read_text(encoding="utf-8"))["vault"]
    print(json.loads((pathlib.Path(vault) / ".keel/current.json").read_text(encoding="utf-8"))["plugin_root"])
except Exception:
    pass
PY
)
    if [ -n "$root" ] && [ -d "$root/engine/keel" ]; then
      @SCAN@
      code=$?
      if [ "$code" -ne 0 ]; then
        echo "@BLOCKED@" >&2
      fi
      exit "$code"
    fi
    echo "Keel: плагін не знайдено, секрети НЕ перевірено, @WHAT@ пропущено. Запусти Claude Code (оновить шлях) або /keel:doctor." >&2
    exit 0
  fi
done
echo "Keel: немає Python 3.11+, секрети НЕ перевірено, @WHAT@ пропущено." >&2
exit 0
"""
_ENV = 'PYTHONPATH="$root/engine" PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1'
PRE_COMMIT = """#!/bin/sh
# keel-managed: перевірка секретів перед комітом. Другий рубіж після хука Claude Code.
# Спрацьовує і для комітів поза Claude. Знахідка чи збій сканера зупиняє коміт.
# Немає плагіна чи Python: попередження без блоку, інакше видалений плагін замкне репозиторій (G21).
""" + (_HOOK_BODY.replace("@SCAN@", f"{_ENV} $c -m keel scan --staged >/dev/null")
       .replace("@BLOCKED@", "Keel: у staged-змінах схоже на секрет, або сканер дав збій. Деталі: python -m keel scan --staged")
       .replace("@WHAT@", "коміт"))
# --no-verify цей хук не вимикає, тому він ловить і коміти без `git commit` (commit-tree, fast-import, am):
# подія тут сам рух гілки, а не текст команди. Потрібен git 2.28+.
REFERENCE_TRANSACTION = """#!/bin/sh
# keel-managed: перевірка нових комітів перед рухом гілки чи тега. Третій рубіж, його не вимикає --no-verify.
[ "$1" = "prepared" ] || { cat >/dev/null; exit 0; }
updates=$(cat)
case "$updates" in
  *refs/heads/*|*refs/tags/*) ;;
  *) exit 0 ;;
esac
if [ -n "$KEEL_ALLOW_SECRET" ]; then
  echo "Keel: KEEL_ALLOW_SECRET задано, нові коміти НЕ перевірено." >&2
  exit 0
fi
""" + (_HOOK_BODY.replace("@SCAN@", f"printf '%s\\n' \"$updates\" | {_ENV} $c -m keel scan --ref-update >&2")
       .replace("@BLOCKED@", "Keel: у нових комітах схоже на секрет, або сканер дав збій; гілку не змінено. "
                             "Свідомо пропустити може лише людина у своєму терміналі: KEEL_ALLOW_SECRET=1 і --no-verify.")
       .replace("@WHAT@", "рух гілки"))
HOOKS = {"pre-commit": PRE_COMMIT, "reference-transaction": REFERENCE_TRANSACTION}
MARKER = "keel-managed"


def slug(root: Path) -> str:
    return re.sub(r"[^\w.\-]+", "-", root.resolve().name) or "project"


def _git_output(root: Path, *args: str) -> str | None:
    done = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, encoding="utf-8", errors="replace")
    return done.stdout.strip() if done.returncode == 0 else None


def hook_plan(root: Path, name: str = "pre-commit") -> dict:
    """Не чіпаємо чужі менеджери хуків: core.hooksPath перебив би husky та pre-commit."""
    git_dir = _git_output(root, "rev-parse", "--git-common-dir")
    if git_dir is None:
        return {"action": "skip", "reason": "не git-репозиторій"}
    if _git_output(root, "config", "--get", "core.hooksPath"):
        return {"action": "skip", "reason": "core.hooksPath уже задано (husky чи подібне): додай `python -m keel scan --staged` у свій хук"}
    path = (root / git_dir).resolve() / "hooks" / name
    if path.exists() and MARKER not in path.read_text(encoding="utf-8", errors="ignore"):
        return {"action": "skip", "reason": f"уже є власний {path.name}: додай `python -m keel scan --staged` у нього"}
    return {"action": "install", "path": str(path)}


def merged_settings(existing: dict, allow: list[str]) -> dict:
    result = json.loads(json.dumps(existing))
    perms = result.setdefault("permissions", {})
    perms["deny"] = sorted(set(perms.get("deny", [])) | set(DENY))
    perms["allow"] = sorted(set(perms.get("allow", [])) | set(allow))
    return result


def _allow_for(stacks) -> list[str]:
    allow = list(BASE_ALLOW)
    for stack in stacks:
        for key in ("test", "lint", "types", "vet"):
            command = stack.commands.get(key, "").split("#")[0].strip()
            if command:
                allow.append(f"Bash({command}*)")
    return allow


def project_toml(stacks, test_command: str) -> str:
    return f"""# Налаштування Keel для цього репозиторію.
stacks = {json.dumps([s.id for s in stacks], ensure_ascii=False)}

[autopilot]
# Автопілот вимкнено. Коли enabled = true, Keel може створювати локальні гілки keel/* з
# патч-оновленнями. Злиття, push і деплой він не робить ніколи.
enabled = false
# Тести оновленої залежності виконують її код. Вмикай, лише якщо розумієш цей ризик.
run_tests = false
test_command = {json.dumps(test_command, ensure_ascii=False)}
# Якщо список заданий, автопілот оновлює лише ці пакети. Порожній означає всі.
# allow = ["lodash", "react"]
"""


def plan(root: Path, vault: Vault, local_settings: bool = False) -> dict:
    root = root.resolve()
    stacks = detect(root)
    name = slug(root)
    settings_path = root / ".claude" / ("settings.local.json" if local_settings else "settings.json")
    existing = read_json(settings_path) or {}
    new_settings = merged_settings(existing, _allow_for(stacks))
    return {
        "project": name, "root": str(root), "stacks": [s.id for s in stacks],
        "maturity": {s.id: s.maturity for s in stacks},
        "commands": {s.id: s.commands for s in stacks},
        "settings_path": str(settings_path),
        "settings_added": {
            "deny": sorted(set(new_settings["permissions"]["deny"]) - set(existing.get("permissions", {}).get("deny", []))),
            "allow": sorted(set(new_settings["permissions"]["allow"]) - set(existing.get("permissions", {}).get("allow", []))),
        },
        "pre_commit": hook_plan(root),
        "ref_hook": hook_plan(root, "reference-transaction"),
        "creates": [".keel/project.toml", ".keel/pitfalls.md", ".keel/adr/"],
    }


def apply(root: Path, vault: Vault, local_settings: bool = False) -> dict:
    root = root.resolve()
    details = plan(root, vault, local_settings)
    stacks = detect(root)
    settings_path = Path(details["settings_path"])
    write_json(settings_path, merged_settings(read_json(settings_path) or {}, _allow_for(stacks)))
    keel = root / ".keel"
    test_command = next((s.commands.get("test", "").split("#")[0].strip() for s in stacks if s.commands.get("test")), "")
    if not (keel / "project.toml").exists():
        write_text(keel / "project.toml", project_toml(stacks, test_command))
    if not (keel / "pitfalls.md").exists():
        write_text(keel / "pitfalls.md", "# Граблі цього проєкту\n\nФормат: що сталося, корінь, правило.\n")
    (keel / "adr").mkdir(parents=True, exist_ok=True)
    for hook, content in ((details["pre_commit"], PRE_COMMIT), (details["ref_hook"], REFERENCE_TRANSACTION)):
        if hook["action"] == "install":
            path = Path(hook["path"])
            write_text(path, content)
            path.chmod(0o755)
    projects = read_json(vault.projects_file) or {}
    projects[details["project"]] = str(root)
    write_json(vault.projects_file, projects)
    return details


def remove_hook(root: Path) -> bool:
    git_dir = _git_output(root, "rev-parse", "--git-common-dir")
    if git_dir is None:
        return False
    removed = False
    for name in HOOKS:
        path = (root / git_dir).resolve() / "hooks" / name
        if path.exists() and MARKER in path.read_text(encoding="utf-8", errors="ignore"):
            path.unlink()
            removed = True
    return removed
