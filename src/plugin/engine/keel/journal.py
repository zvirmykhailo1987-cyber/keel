"""Журнал подій: лише дописування, місячні сегменти, знімки згорток.
Старт не читає всю історію: згортка продовжує зі збереженої позиції."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Iterator

from . import clock
from .fsutil import FileLock, read_json, write_json


class JournalCorrupt(RuntimeError):
    pass


class Journal:
    def __init__(self, directory: Path, snapshots: Path | None = None):
        self.dir = Path(directory)
        self.snapshots = Path(snapshots) if snapshots else self.dir.parent / "snapshots"
        self.lock = self.dir / ".lock"

    def append(self, kind: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        moment = clock.now()
        data = data or {}
        body = json.dumps({"kind": kind, "data": data}, ensure_ascii=False, sort_keys=True)
        event = {
            "ts": clock.iso(moment),
            "id": hashlib.sha256(f"{clock.iso(moment)}|{body}".encode()).hexdigest()[:12],
            "kind": kind,
            "data": data,
        }
        path = self.dir / f"{moment:%Y-%m}.jsonl"
        self.dir.mkdir(parents=True, exist_ok=True)
        with FileLock(self.lock):
            with path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
        return event

    def segments(self) -> list[Path]:
        return sorted(self.dir.glob("*.jsonl")) if self.dir.exists() else []

    def _read(self, path: Path, skip: int = 0) -> Iterator[tuple[int, dict[str, Any]]]:
        lines = path.read_text(encoding="utf-8").split("\n")
        complete = lines[:-1]  # після останнього \n порожньо; інакше хвіст обірваний збоєм
        for number, line in enumerate(complete, 1):
            if number <= skip:
                continue
            try:
                yield number, json.loads(line)
            except ValueError as exc:
                raise JournalCorrupt(f"{path.name}:{number}") from exc

    def events(self) -> Iterator[dict[str, Any]]:
        for path in self.segments():
            for _, event in self._read(path):
                yield event

    def fold(self, name: str, reducer: Callable[[Any, dict[str, Any]], Any], initial: Any,
             version: int = 1) -> Any:
        """Згортка зі знімком. Зміна version перераховує все з нуля."""
        snap_path = self.snapshots / f"{name}.json"
        snap = read_json(snap_path) or {}
        if snap.get("version") != version:
            snap = {}
        state = snap.get("state", initial)
        pos_segment, pos_line = snap.get("segment", ""), snap.get("line", 0)
        changed = False
        for path in self.segments():
            if path.name < pos_segment:
                continue
            skip = pos_line if path.name == pos_segment else 0
            for number, event in self._read(path, skip):
                state = reducer(state, event)
                pos_segment, pos_line = path.name, number
                changed = True
        if changed:
            write_json(snap_path, {"version": version, "segment": pos_segment,
                                   "line": pos_line, "state": state})
        return state
