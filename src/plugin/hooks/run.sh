#!/bin/sh
# Запускач Keel: знаходить Python 3.11+ і передає керування engine.
# Якщо інтерпретатора немає, код 2 (для PreToolUse це блокування, а не тихий пропуск).
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHONUTF8=1; PYTHONIOENCODING=utf-8; PYTHONDONTWRITEBYTECODE=1; export PYTHONUTF8 PYTHONIOENCODING PYTHONDONTWRITEBYTECODE
PYTHONPATH="$root/engine"; export PYTHONPATH
for c in python3 python "py -3"; do
  if $c -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then
    exec $c "$@"
  fi
done
echo "Keel: не знайдено Python 3.11+. Встанови його або вимкни плагін через /plugin." >&2
exit 2
