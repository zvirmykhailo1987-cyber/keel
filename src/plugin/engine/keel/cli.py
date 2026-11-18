"""Командний рядок рушія: `python -m keel <команда>`. Команди плагіна викликають саме його."""
from __future__ import annotations

import argparse
import json
import os
import sys
import unittest
from pathlib import Path

from .paths import CONFIG_FILE, Vault, home


def _print(value) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def cmd_scan(args) -> int:
    from . import secretscan
    if args.ref_update:
        found = secretscan.scan_ref_update(Path.cwd(), sys.stdin.read().splitlines())
    elif args.staged:
        found = secretscan.scan_staged(Path.cwd())
    elif args.paths:
        found = secretscan.scan_paths([Path(p) for p in args.paths])
    else:  # «нічого не перевірив» не має виглядати як «чисто» (G22)
        print("Вкажи шлях або --staged: без цілі перевіряти нічого.", file=sys.stderr)
        return 2
    _print({"clean": not found, "findings": [f.as_dict() for f in found]})
    return 1 if found else 0


def cmd_selftest(_args) -> int:
    engine = Path(__file__).resolve().parents[1]
    suite = unittest.defaultTestLoader.discover(str(engine / "keel_tests"), top_level_dir=str(engine))
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=1).run(suite)
    if result.testsRun == 0:
        print("Жодного тесту не знайдено: це збій, а не успіх (G52).", file=sys.stderr)
        return 1
    return 0 if result.wasSuccessful() else 1


def cmd_setup(args) -> int:
    from .flow.executor import write_settings_default
    from .flow.gitsafe import commit_all, ensure_repo
    from .fsutil import write_json, write_text
    from .scheduler import install_shim
    from .session import sync_current
    vault = Vault(Path(args.vault).expanduser()) if args.vault else Vault.default()
    vault.init()
    write_json(home() / CONFIG_FILE, {"vault": str(vault.root)})
    write_settings_default(vault)
    install_shim(vault)
    sync_current(vault)
    if not (vault.root / "README.md").exists():
        write_text(vault.root / "README.md", "# Vault Keel\n\nОсобисті знання. Обсидіан відкриває цю теку напряму. "
                                             "`.keel/state` веде рушій, вручну не правити.\n")
    write_text(vault.root / ".gitignore", ".keel/cache/\n.keel/state/\n.keel/reports/\n*.tmp\n")
    ensure_repo(vault.root)
    commit_all(vault.root, "vault: старт")
    _print({"vault": str(vault.root), "background": False, "schedule": False})
    return 0


def _vault() -> Vault:
    vault = Vault.default()
    if not vault.exists:
        raise SystemExit("Keel ще не налаштовано: виконай /keel:setup")
    return vault


def cmd_init_project(args) -> int:
    from . import project
    vault = _vault()
    root = Path(args.path)
    _print(project.apply(root, vault, args.local) if args.apply else project.plan(root, vault, args.local))
    return 0


def cmd_radar(args) -> int:
    from .flow import pipeline
    from .radar import engine
    vault = _vault()
    result = engine.run(vault, force=args.force)
    actions = pipeline.process(vault, result["new"])
    _print({"new": len(result["new"]), "total": result["total"], "unchecked": result["unchecked"],
            "source_errors": result["errors"], "projects": result["projects"], "actions": actions,
            "report": result["report"]})
    return 0


def cmd_tick(args) -> int:
    from . import tick
    _print(tick.run(_vault(), force_radar=args.force))
    return 0


def cmd_decide(args) -> int:
    from .flow.cards import Cards
    from .flow.executor import Executor
    from .tick import apply_decisions
    vault = _vault()
    cards = Cards(vault)
    if args.list:
        cards.render()
        today, backlog = cards.today()
        _print({"today": today, "backlog": len(backlog), "html": str(vault.reports / "decisions.html"),
                "markdown": str(vault.root / "inbox" / "DECISIONS.md")})
        return 0
    executor = Executor(vault)
    if args.file:
        payload = json.loads(Path(args.file).read_text(encoding="utf-8"))
        outcome = apply_decisions(vault, executor, payload)
    elif args.id:
        if args.verdict is None:  # мовчання людини не є згодою
            raise SystemExit("Вкажи рішення явно: decide <id> yes або decide <id> no")
        status = {"yes": "approved", "no": "rejected"}[args.verdict]
        card = cards.resolve(args.id, status, "human", args.comment)
        outcome = [{"id": args.id, "status": status,
                    "outcome": executor.apply_approved(card) if status == "approved" else None}]
    else:
        outcome = apply_decisions(vault, executor)
    cards.render()
    _print(outcome)
    return 0


def cmd_done(args) -> int:
    """Людина сама виконала Tier 3 і позначає це."""
    from .flow.cards import Cards
    _print(Cards(_vault()).resolve(args.id, "done", "human", args.comment))
    return 0


def cmd_undo(args) -> int:
    from .flow.executor import Executor
    _print(Executor(_vault()).undo(args.event))
    return 0


def cmd_propose(args) -> int:
    """Вхід для сесій Claude: пропозиція проходить той самий контроль, що й фонова."""
    from .flow.executor import Executor
    raw = Path(args.file).read_text(encoding="utf-8") if args.file else sys.stdin.read()
    data = json.loads(raw)
    items = data.get("proposals", [data]) if isinstance(data, dict) else data
    executor = Executor(_vault())
    _print([executor.propose(p, origin="model") for p in items])
    return 0


def cmd_autopilot(args) -> int:
    from .flow import quanta
    from .fsutil import write_json
    from .scheduler import Scheduler, install_shim
    vault = _vault()
    settings = quanta.load_settings(vault)
    if args.mode == "status":
        _print({"settings": settings, "schedule": Scheduler(vault).verify(), "quota_left": quanta.quota_left(vault)})
    elif args.mode == "schedule":
        sched = Scheduler(vault)
        if not args.apply:
            print(sched.plan().describe())
            return 0
        install_shim(vault)
        sched.apply()
        settings["schedule_enabled"] = True
        write_json(vault.settings_file, settings)
        _print({"registered": sched.registered()})
    elif args.mode == "unschedule":
        Scheduler(vault).remove()
        settings["schedule_enabled"] = False
        write_json(vault.settings_file, settings)
        _print({"registered": False})
    elif args.mode in quanta.PRESETS:
        _print(quanta.set_preset(vault, args.mode))
    return 0


def cmd_verify_fact(args) -> int:
    from .flow import citeguard
    status, checks = citeguard.verify_fact(args.url, args.quote, args.second_url or "", args.second_quote or "",
                                           args.strong, _vault().cache / "http")
    _print({"status": status, "checks": [vars(c) for c in checks]})
    return 0 if status == citeguard.VERIFIED else 1


def cmd_learn(args) -> int:
    from .growth import skillmap
    vault = _vault()
    if args.evidence:
        _print(skillmap.add_evidence(vault, args.skill, args.evidence, args.level))
    elif args.card:
        _print(skillmap.add_card(vault, args.card, args.front, args.back))
    elif args.review:
        _print(skillmap.review(vault, args.review, args.quality))
    else:
        _print(skillmap.next_step(vault))
    return 0


def cmd_overlay(args) -> int:
    from .growth import trials
    vault = _vault()
    if args.fail:
        _print(trials.report_failure(vault, args.skill, args.note or ""))
    else:
        text = Path(args.file).read_text(encoding="utf-8")
        _print(trials.propose(vault, args.skill, text, args.reason or "без причини"))
    return 0


def cmd_doctor(_args) -> int:
    from . import doctor
    report = doctor.run()
    _print(report)
    return 1 if report["status"] == doctor.FAIL else 0


def cmd_uninstall(args) -> int:
    from . import project
    from .fsutil import read_json
    from .scheduler import Scheduler
    vault = Vault.default()
    projects = read_json(vault.projects_file) or {}
    plan = {"scheduler_task": True, "git_hooks_in": list(projects), "vault_kept": str(vault.root)}
    if not args.apply:
        _print(plan)
        return 0
    Scheduler(vault).remove()
    removed = [name for name, path in projects.items() if Path(path).is_dir() and project.remove_hook(Path(path))]
    _print({"scheduler_removed": True, "hooks_removed": removed, "vault_kept": str(vault.root),
            "next": "Виконай /plugin uninstall keel"})
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="keel")
    sub = parser.add_subparsers(dest="command", required=True)

    def add(name, func, help_text):
        item = sub.add_parser(name, help=help_text)
        item.set_defaults(func=func)
        return item

    p = add("scan", cmd_scan, "сканер секретів")
    p.add_argument("paths", nargs="*")
    p.add_argument("--staged", action="store_true")
    p.add_argument("--ref-update", action="store_true", help="stdin хука reference-transaction")
    add("selftest", cmd_selftest, "власні тести рушія")
    p = add("setup", cmd_setup, "створити vault")
    p.add_argument("--vault")
    p = add("init-project", cmd_init_project, "підключити репозиторій")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--local", action="store_true", help="писати settings.local.json (для чужих репо)")
    p = add("radar", cmd_radar, "прогін Radar")
    p.add_argument("--force", action="store_true")
    p = add("tick", cmd_tick, "повний цикл")
    p.add_argument("--force", action="store_true")
    p = add("decide", cmd_decide, "рішення")
    p.add_argument("--list", action="store_true")
    p.add_argument("--file")
    p.add_argument("id", nargs="?")
    p.add_argument("verdict", nargs="?", choices=["yes", "no"])
    p.add_argument("--comment", default="")
    p = add("done", cmd_done, "людина виконала Tier 3")
    p.add_argument("id")
    p.add_argument("--comment", default="")
    p = add("undo", cmd_undo, "відкат дії Tier 1")
    p.add_argument("event")
    p = add("propose", cmd_propose, "подати пропозицію")
    p.add_argument("--file")
    p = add("autopilot", cmd_autopilot, "фон і планувальник")
    p.add_argument("mode", choices=["status", "schedule", "unschedule", "off", "low", "max"])
    p.add_argument("--apply", action="store_true")
    p = add("verify-fact", cmd_verify_fact, "перевірити цитату на сторінці")
    p.add_argument("url")
    p.add_argument("quote")
    p.add_argument("--second-url")
    p.add_argument("--second-quote")
    p.add_argument("--strong", action="store_true")
    p = add("learn", cmd_learn, "карта розвитку")
    p.add_argument("--skill", default="")
    p.add_argument("--evidence")
    p.add_argument("--level", type=int)
    p.add_argument("--card")
    p.add_argument("--front", default="")
    p.add_argument("--back", default="")
    p.add_argument("--review")
    p.add_argument("--quality", type=int, default=4)
    p = add("overlay", cmd_overlay, "уточнення навички")
    p.add_argument("skill")
    p.add_argument("--file")
    p.add_argument("--reason")
    p.add_argument("--fail", action="store_true")
    p.add_argument("--note")
    add("doctor", cmd_doctor, "діагностика")
    p = add("uninstall", cmd_uninstall, "прибрати задачі й хуки, vault лишити")
    p.add_argument("--apply", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8")
    os.environ.setdefault("PYTHONUTF8", "1")
    args = build_parser().parse_args(argv)
    return args.func(args)
