"""Сканер секретів. Секрет у git означає ротацію, тому помилка тут дорога в обидва боки:
пропуск шкодить одразу, а хибні тривоги змушують гейт вимкнути (G21)."""
from __future__ import annotations

import math
import os
import re
import subprocess
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

# Форма однозначна: значення визначає секрет. Прагма такі знахідки не вимикає.
SHAPE_PATTERNS = [
    ("private-key", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ("aws-access-key", r"\bAKIA[0-9A-Z]{16}\b"),
    ("google-api-key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("slack-token", r"\bxox[baprs]-[0-9A-Za-z\-]{10,}"),
    ("github-token", r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"),
    ("github-fine-grained", r"\bgithub_pat_[0-9A-Za-z_]{40,}\b"),
    ("gitlab-token", r"\bglpat-[0-9A-Za-z_\-]{20,}\b"),
    ("anthropic-key", r"\bsk-ant-[0-9A-Za-z_\-]{20,}\b"),
    ("openai-key", r"\bsk-(?:proj-|svcacct-)?[0-9A-Za-z_\-]{32,}\b"),
    ("stripe-live-key", r"\b[sr]k_live_[0-9A-Za-z]{20,}\b"),
    ("npm-token", r"\bnpm_[0-9A-Za-z]{36}\b"),
    ("pypi-token", r"\bpypi-[0-9A-Za-z_\-]{50,}\b"),
    ("huggingface-token", r"\bhf_[0-9A-Za-z]{30,}\b"),
    ("telegram-bot-token", r"\b\d{8,10}:[0-9A-Za-z_\-]{35}\b"),
    ("sendgrid-key", r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b"),
    ("twilio-key", r"\bSK[0-9a-fA-F]{32}\b"),
    ("shopify-token", r"\bshp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}\b"),
    ("digitalocean-token", r"\bdo[por]_v1_[0-9a-f]{64}\b"),
    ("azure-storage-key", r"\bAccountKey=[0-9A-Za-z+/]{80,}={0,2}"),
]
# Значення у групі "v": рядковий літерал, а не вираз.
ASSIGN_PATTERNS = [
    ("bat-secret", r'(?i)\bset\s+"\w*(?:api[_-]?key|secret|password|passwd|token)\s*=\s*(?P<v>[^"\r\n]{8,})"'),
    ("ps-secret", r"(?i)\$(?:env:)?\w*(?:api[_-]?key|secret|password|token)\s*=\s*(['\"])(?P<v>[^'\"]{8,})\1"),
    ("generic-secret", r"(?i)[\"']?\w*(?:api[_-]?key|secret|password|passwd|token)[\"']?\s*[:=]\s*(['\"])(?P<v>[^'\"]{8,})\1"),
    ("dsn-password", r"\b[a-z][a-z0-9+]{2,}://[^\s:/@'\"]+:(?P<v>[^\s@'\"]{8,})@[^\s'\"]+"),
    # JWT живе тут, а не серед форм: тестові токени у фікстурах звичні, і для них має діяти прагма.
    ("jwt", r"(?P<v>\beyJ[0-9A-Za-z_\-]{10,}\.eyJ[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,})"),
]
_SHAPES = [(n, re.compile(p)) for n, p in SHAPE_PATTERNS]
_ASSIGNS = [(n, re.compile(p)) for n, p in ASSIGN_PATTERNS]
ASSIGN_TYPES = {n for n, _ in ASSIGN_PATTERNS}
PRAGMA = re.compile(r"secret-scan:\s*ignore")
_PLACEHOLDER_VALUE = re.compile(
    r"(?i)^(?:your|example|placeholder|changeme|dummy|sample|demo|fake|test|xxx|<|\$\{|%\w+%|\$\w+)|"
    r"\.\.\.|env\(|os\.environ|getenv|process\.env")
_COMMENT = re.compile(r"^\s*(?:#|//|rem\s|--|;)", re.I)
TEXT_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".env", ".bat", ".cmd", ".sh",
                 ".ps1", ".json", ".yml", ".yaml", ".md", ".txt", ".cfg", ".ini", ".toml", ".html",
                 ".go", ".rs", ".java", ".kt", ".cs", ".php", ".rb", ".swift", ".c", ".h", ".cpp",
                 ".hpp", ".tf", ".properties", ".xml", ".conf", ".gradle", ".sql", ""}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "target",
             "vendor", ".gradle", "Pods", "bin", "obj"}
MAX_LINE = 4000


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    type: str
    preview: str

    def as_dict(self) -> dict:
        return asdict(self)


def entropy(value: str) -> float:
    if not value:
        return 0.0
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in Counter(value).values())


def _preview(value: str) -> str:
    return value[:4] + "…" if len(value) > 4 else "…"


# Склейка рядкових літералів: `"AKIA" + "…"`, `'a' 'b'`, `"a" .. "b"`, і те саме через перенос рядка.
_JOIN = re.compile(r"""(["'])[ \t]*(?:\+|\.\.|\.|&)?[ \t]*\\?[ \t]*\n?[ \t]*(?:\+|\.\.|\.|&)?[ \t]*(["'])""")
_B64 = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{24,}={0,2}")
_HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){16,}(?![0-9A-Fa-f])")
_ESCAPED = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){8,}")
_WINDOW = 4  # скільки сусідніх рядків склеюємо: значення, розбите на більше, гейт не побачить (README)
MAX_SCAN = 2_000_000


def _shapes(text: str) -> list[tuple[str, str]]:
    """Форми по всій довжині рядка, вікнами з перекриттям: довгий рядок (мініфікований чи бінарний) не ховає ключ."""
    found: list[tuple[str, str]] = []
    text = text[:MAX_SCAN]
    for start in range(0, max(len(text), 1), MAX_LINE):
        chunk = text[start:start + MAX_LINE + 200]
        for name, rx in _SHAPES:
            for match in rx.finditer(chunk):
                found.append((name, match.group(0)))
    return found


def _printable(data: bytes) -> str | None:
    text = data.decode("latin-1")
    good = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
    return text if text and good / len(text) >= 0.9 else None


def _decoded(line: str) -> list[tuple[str, str]]:
    """Ключ у base64, hex чи `\\x..`: шукаємо ті самі форми в розкодованому вмісті."""
    import base64
    import binascii
    found: list[tuple[str, str]] = []
    candidates: list[bytes] = []
    for match in _B64.finditer(line):
        token = match.group(0).rstrip("=").replace("-", "+").replace("_", "/")
        try:
            candidates.append(base64.b64decode(token + "=" * (-len(token) % 4), validate=True))
        except (binascii.Error, ValueError):
            pass
    for match in _HEX.finditer(line):
        candidates.append(bytes.fromhex(match.group(0)))
    for match in _ESCAPED.finditer(line):
        candidates.append(bytes.fromhex(match.group(0).replace("\\x", "")))
    for data in candidates:
        text = _printable(data)
        if text:
            found += [(f"{name} (encoded)", value) for name, value in _shapes(text)]
    return found


def scan_text(text: str, path: str = "<text>", file_pragma_allowed: bool = True) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    file_pragma = file_pragma_allowed and bool(PRAGMA.search("\n".join(lines[:5])))
    seen: set[str] = set()
    for number, line in enumerate(lines, 1):
        shapes = _shapes(line) or _decoded(line)
        if shapes:
            name, value = shapes[0]
            seen.update(v for _, v in shapes)
            findings.append(Finding(path, number, name, _preview(value)))
            continue
        line = line[:MAX_LINE]
        if file_pragma or PRAGMA.search(line) or _COMMENT.match(line):
            continue
        for name, rx in _ASSIGNS:
            match = rx.search(line)
            if not match:
                continue
            value = match.group("v")
            if _PLACEHOLDER_VALUE.search(value) or len(value) < 12 or entropy(value) < 3.0:
                continue
            findings.append(Finding(path, number, name, _preview(value)))
            break
    if _JOIN.search(text):
        for index in range(len(lines)):
            window = "\n".join(lines[index:index + _WINDOW])
            if not _JOIN.search(window):
                continue
            for name, value in _shapes(_JOIN.sub("", window)):
                if value not in seen:
                    seen.add(value)
                    findings.append(Finding(path, index + 1, f"{name} (split)", _preview(value)))
    return findings


# Сканер читає чужий репозиторій, тому його конфіг і середовище для нас ворожі: `diff.external`,
# textconv чи атрибут `-diff` інакше ховають секрет від перевірки. Жива звірка: 0 знахідок на ключі.
_DIFF_FLAGS = ["--no-ext-diff", "--no-textconv", "--text", "--no-color", "-U0"]
_HOSTILE_ENV = {"GIT_EXTERNAL_DIFF", "GIT_DIFF_OPTS", "GIT_PAGER", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT"}


def _git(args: list[str], cwd: Path, timeout: float = 120) -> str:
    env = {k: v for k, v in os.environ.items() if k not in _HOSTILE_ENV}
    done = subprocess.run(["git", "-c", "core.quotepath=false", "-c", "core.fsmonitor=false", *args], cwd=cwd,
                          capture_output=True, timeout=timeout, env=env)
    if done.returncode != 0:
        raise RuntimeError(f"git {args[0]}: код {done.returncode}")
    return done.stdout.decode("utf-8", errors="replace")


def is_git_ignored(path: Path) -> bool:
    """Секрет у файлі поза git не є порушенням: правило звучить «не в git»."""
    path = Path(path).resolve()
    parent = path.parent
    while not parent.exists() and parent != parent.parent:
        parent = parent.parent
    try:
        done = subprocess.run(["git", "check-ignore", "-q", str(path)], cwd=parent,
                              capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return done.returncode == 0


def scan_diff(diff: str) -> list[Finding]:
    """Лише додані рядки з unified diff (-U0). Суміжні додані рядки скануються блоком, щоб
    побачити значення, розбите на кілька рядків. Прагма діє лише в межах свого рядка."""
    findings: list[Finding] = []
    current, line_no, block, start = "<diff>", 0, [], 0

    def flush() -> None:
        nonlocal block
        if block:
            for finding in scan_text("\n".join(block), current, file_pragma_allowed=False):
                findings.append(Finding(current, start + finding.line - 1, finding.type, finding.preview))
        block = []

    for raw in diff.splitlines():
        if raw.startswith("+++ "):
            flush()
            current = raw[4:].removeprefix("b/")
        elif raw.startswith("@@"):
            flush()
            match = re.search(r"\+(\d+)", raw)
            line_no = int(match.group(1)) if match else 0
        elif raw.startswith("+"):
            if not block:
                start = line_no
            block.append(raw[1:])
            line_no += 1
        else:
            flush()
    flush()
    return findings


def scan_staged(repo: Path) -> list[Finding]:
    return scan_diff(_git(["diff", "--cached", *_DIFF_FLAGS], repo))


def _has_head(repo: Path) -> bool:
    done = subprocess.run(["git", "rev-parse", "--verify", "-q", "HEAD"], cwd=repo,
                          capture_output=True, timeout=10)
    return done.returncode == 0


def scan_worktree_changes(repo: Path) -> list[Finding]:
    """Для `git add ... && git commit`: хук бачить стан ДО add, тому дивимось на все змінене."""
    findings: list[Finding] = []
    if _has_head(repo):
        findings += scan_diff(_git(["diff", "HEAD", *_DIFF_FLAGS], repo))
    else:
        findings += scan_staged(repo)
    for name in _git(["ls-files", "-o", "--exclude-standard"], repo).splitlines():
        text = _file_text(repo / name)
        if text is not None:
            findings += scan_text(text, name)
    return findings


def _file_text(path: Path) -> str | None:
    """Будь-який файл, і бінарний теж: суфікс не гарантує, що всередині немає ключа."""
    try:
        if not path.is_file() or path.stat().st_size > MAX_SCAN:
            return None
        return path.read_bytes().decode("utf-8", errors="ignore")
    except OSError:
        return None


def scan_unpushed(repo: Path, limit: int = 200) -> list[Finding]:
    findings: list[Finding] = []
    # Усі локальні гілки й теги: `git push origin other` відправляє не лише те, що досяжне з HEAD.
    commits = _git(["rev-list", f"--max-count={limit}", "HEAD", "--branches", "--tags", "--not", "--remotes"], repo).split()
    for commit in commits:
        findings += scan_diff(_git(["show", "--pretty=format:", *_DIFF_FLAGS, commit], repo))
    return findings


_NULL_SHA = re.compile(r"^0+$")


def scan_ref_update(repo: Path, updates: list[str], limit: int = 200) -> list[Finding]:
    """Для хука reference-transaction, стан prepared: гілки ще на старих значеннях.

    Дивимось лише коміти, яких нема в жодній гілці, тезі чи remote: звичайний рух гілки, fetch і
    pull нічого нового не додають, тож перевірка їх не чіпає. HEAD без гілки не перевіряємо:
    огляд чужого PR через FETCH_HEAD не має блокуватись, а коміт відстане на створенні гілки."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for line in updates:
        parts = line.split()
        if len(parts) != 3:
            continue
        _old, new, ref = parts
        if _NULL_SHA.match(new) or not ref.startswith(("refs/heads/", "refs/tags/")):
            continue
        commits = _git(["rev-list", f"--max-count={limit}", new, "--not", "--branches", "--tags", "--remotes"], repo).split()
        if len(commits) >= limit:  # G43: обрізання не має бути мовчазним
            print(f"Keel: перевірено лише {limit} нових комітів для {ref}, решту НЕ перевірено.", file=sys.stderr)
        for commit in commits:
            if commit not in seen:
                seen.add(commit)
                findings += scan_diff(_git(["show", "--pretty=format:", *_DIFF_FLAGS, commit], repo))
    return findings


def scan_paths(paths: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for root in paths:
        root = Path(root)
        files = [root] if root.is_file() else [
            p for p in root.rglob("*")
            if p.is_file() and not (set(p.relative_to(root).parts) & SKIP_DIRS)
        ]
        for path in files:
            text = _file_text(path)
            if text is not None:
                findings += scan_text(text, str(path))
    return findings
