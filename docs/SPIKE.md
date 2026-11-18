# W0: перевірені факти (Claude Code 2.1.268, Windows 11, 06.11.2026)

| Питання | Результат | Як перевірено |
|---|---|---|
| PreToolUse exit 2 | блокує Write | `claude -p --plugin-dir`, файл не створено |
| PreToolUse: збій Python (exit 1) | НЕ блокує, файл створено | той самий прогін |
| exec-форма `args` | працює, якщо команда є в PATH процесу | `python` спрацював |
| Запуск через `sh hooks/run.sh` | працює, exit 2 проходить через exec | прогін із маркером блокування |
| Простір імен команд | `/keel:ping` виконалась | прогін |
| Marketplace у теці + чистий `CLAUDE_CONFIG_DIR` | add/install/list працюють без входу | `claude plugin ...` |
| `--disallowedTools`, `--json-schema`, `dontAsk` | є в `claude --help` | читання довідки |
| `CLAUDE_PLUGIN_DATA` | `~/.claude/plugins/data/keel-inline` при `--plugin-dir` | лог хука |

## Наслідки для дизайну
- Fail-closed не можна покласти на код виходу інтерпретатора: потрібен catch-all у guard, що перетворює збій на exit 2.
- Якщо немає Python, `run.sh` повертає 2. Якщо немає навіть `sh` (Windows без Git Bash), хук не спрацює: тому другий рубіж git pre-commit і перевірка в doctor.
- Прогони `claude -p` бачать глобальні налаштування власника. Наскрізний тест поведінки треба ізолювати, інакше результат забруднено: у тестовій відповіді модель згадала власника.

## Не перевірено досі
- SessionStart additionalContext у чистому профілі (вивід обрізався).
- macOS і Linux: Linux перевіримо через WSL; macOS лише в CI після створення репо.
