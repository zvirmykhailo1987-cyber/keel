"""Файлові операції: атомарний запис, UTF-8 + LF, блокування без PID (G49)."""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any


def write_text(path: Path, text: str) -> None:
    """Атомарний запис. Завжди UTF-8 і LF, незалежно від ОС."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default


def write_json(path: Path, value: Any) -> None:
    write_text(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


class LockBusy(RuntimeError):
    pass


class FileLock:
    """Блокування через O_EXCL. Застарілість визначається за часом файлу, а не за PID:
    після перезавантаження номер процесу може дістатися чужому (G49)."""

    def __init__(self, path: Path, stale_seconds: float = 900, wait_seconds: float = 10):
        self.path, self.stale, self.wait = Path(path), stale_seconds, wait_seconds

    def __enter__(self) -> "FileLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self.wait
        while True:
            try:
                os.close(os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
                return self
            except FileExistsError:
                try:
                    if time.time() - self.path.stat().st_mtime > self.stale:
                        self.path.unlink(missing_ok=True)
                        continue
                except FileNotFoundError:
                    continue
            except PermissionError:
                pass  # Windows: інший процес саме видаляє файл
            if time.monotonic() >= deadline:
                raise LockBusy(str(self.path))
            time.sleep(0.05)

    def __exit__(self, *_exc: object) -> None:
        self.path.unlink(missing_ok=True)
