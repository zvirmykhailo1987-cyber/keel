"""PreToolUse-хук: секрети й стан Keel.

Будь-який збій перевірки запису чи коміту стає блокуванням (код 2). Перевірений факт:
необроблений виняток дає код 1, а такий код Claude Code НЕ сприймає як заборону (docs/SPIKE.md).
Читання й звичайні команди збій не блокує, бо гейт, що заважає працювати, вимкнуть (G21).

Це страховка, а не межа: розбір тексту команди не бачить скрипта з файлу чи рядка, зібраного під час
виконання. Жорстку межу дає лише сервер: push protection або сканер секретів у CI (README).
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import sys
from pathlib import Path

from . import secretscan
from .paths import Vault

_SEGMENT = r"[^;&|\n]*"
GIT_COMMIT = re.compile(rf"\bgit\b{_SEGMENT}\bcommit\b")
GIT_PUSH = re.compile(rf"\bgit\b{_SEGMENT}\bpush\b")
GIT_ADD = re.compile(rf"\bgit\b{_SEGMENT}\b(?:add|stage)\b")
COMMIT_ALL = re.compile(rf"\bcommit\b{_SEGMENT}\s(?:-[a-zA-Z]*a[a-zA-Z]*|--all)(?:\s|$)")
COMMIT_ARGS = re.compile(rf"\bgit\b{_SEGMENT}?\bcommit\b({_SEGMENT})")
# git приймає однозначні скорочення довгих опцій, тому --no-veri це те саме, що --no-verify.
NO_VERIFY = re.compile(rf"\bgit\b{_SEGMENT}\b(?:commit|push|merge|am|rebase|cherry-pick)\b{_SEGMENT}\s--no-veri\w*|"
                       rf"\bgit\b{_SEGMENT}\bcommit\b{_SEGMENT}\s-(?!-)[a-zA-Z]*n[a-zA-Z]*(?:\s|$)")
_SHELLS = r"(?:ba|z|da|k|a|c|tc|fi)?sh(?:\.exe)?"
_INTERPRETERS = r"(?:python[\d.]*|py|node|deno|bun|perl|ruby|php|lua)(?:\.exe)?"
_RUNNERS = rf"(?:{_SHELLS}|{_INTERPRETERS}|pwsh(?:\.exe)?|powershell(?:\.exe)?)"
# Команда всередині цих конструкцій стоїть у лапках або приходить через stdin, тож вирізати її не можна.
INDIRECT = re.compile(
    rf"\b{_SHELLS}\b{_SEGMENT}\s-[a-zA-Z]*c\b|"
    rf"\b(?:pwsh|powershell)(?:\.exe)?\b{_SEGMENT}\s-(?:c|command)\b|"
    rf"\bcmd(?:\.exe)?\b{_SEGMENT}\s/[ck]\b|"
    rf"\b{_INTERPRETERS}\b{_SEGMENT}\s-[a-zA-Z]*[cer]\b|"
    rf"\b{_RUNNERS}\b{_SEGMENT}(?:<<|<\()|"
    rf"\|\s*{_RUNNERS}\b|\bsource\b{_SEGMENT}<\(|"
    r"\beval\b|\biex\b|\bInvoke-Expression\b|\bxargs\b|\bStart-Process\b|\bsaps\b|\bStart-Job\b|\bInvoke-Command\b|\bicm\b", re.I)
_FEEDS_HEREDOC = re.compile(rf"\b{_RUNNERS}\b", re.I)
_HEREDOC = re.compile(r"<<-?\s*(['\"]?)(\w+)\1[^\n]*\n.*?\n\s*\2[ \t]*(?=\n|$)", re.S)
# Вміст, який гейт не може прочитати. Хибна тривога тут дешевша за пропуск.
OPAQUE = re.compile(rf"\b(?:pwsh|powershell)(?:\.exe)?\b{_SEGMENT}\s-e(?:nc\w*|c)?\b|"
                    rf"\bbase64\b[^;\n]*\|\s*{_RUNNERS}\b", re.I)
GIT_WRAPPER_DEF = re.compile(r"\b\w+\s*\(\s*\)\s*\{[^}]*\bgit\b|\bfunction\s+[\w-]+[^{]*\{[^}]*\bgit\b|"
                             r"\balias\s+\w+=\S*git\b|\bSet-Alias\b[^;&|\n]*\bgit\b", re.I)
_EXPANSION = re.compile(r"\$\{?\w+\}?(?=\s)|\$\([^)]*\)(?=\s)|`[^`]*`(?=\s)")
_KEEP_QUOTED = re.compile(r"(?i)\.git[. ]*[/\\]|git~\d|alias\.|hookspath|include(?:if)?\.|diff\.|fsmonitor|attributesfile|sshcommand|filter\.|secret-scan|\.claude[/\\]|\.mcp\.json")
_ANSI_C = re.compile(r"\$'([^']*)'")
_GLOBBED_NAMES = ("git", "commit", "push", "add")
_CONFIG_TAMPER = re.compile(rf"\bgit\b{_SEGMENT}(?:\bconfig\b|\s-c\s|\s--config-env\b){_SEGMENT}"
                            r"(?i:core\.hookspath|alias\.|include(?:if)?\.|diff\.external|diff\.[\w-]+\.(?:command|textconv)|"
                            r"core\.fsmonitor|core\.attributesfile|core\.sshcommand|filter\.[\w-]+\.(?:clean|smudge|process|required))")
_CONFIG_READ = re.compile(r"\bconfig\s+(?:--get\S*|--list|-l|get|list)(?:\s|$)")
# Windows знімає крапку в кінці сегмента, не зважає на регістр і знає імена 8.3: `.git.`, `.GIT`, `GIT~1`.
_GIT_META = r"(?:\S*[/\\])?(?:\.git[. ]*|git~\d)[/\\]+(?:hooks|config)\b"
_WRITERS = (r"(?:\b(?:rm|mv|cp|chmod|chown|tee|truncate|ln|dd|install|del|erase|ren|rename|rd|rmdir|move|copy|attrib|icacls|ri|"
            r"Remove-Item|Set-Content|Add-Content|Clear-Content|Out-File|Move-Item|Copy-Item|New-Item|Rename-Item)\b|"
            r"\bsed\s+-i|--output[=\s]|>)")
HOOK_FILES = re.compile(rf"(?i){_WRITERS}{_SEGMENT}{_GIT_META}|"
                        r"\b(?:cd|pushd|Set-Location|sl)\s+(?:\S*[/\\])?\.git(?:[/\\]\S*)?(?:\s|$)")
_HOOK_ENV_NAMES = r"(?:GIT_\w+|HUSKY\w*|LEFTHOOK|SKIP|KEEL_\w+|ANTHROPIC_BASE_URL)"
ENV_TAMPER = re.compile(r"\b(?:GIT_CONFIG_\w+|GIT_EXTERNAL_DIFF|GIT_EXEC_PATH|KEEL_ALLOW_SECRET|ANTHROPIC_BASE_URL)\s*=|"
                        rf"\bgit\b{_SEGMENT}--exec-path=|"
                        rf"(?i:\b(?:Set-Item|New-Item|sv)\s+(?:-Path\s+)?Env:{_HOOK_ENV_NAMES}\b|SetEnvironmentVariable{_SEGMENT}{_HOOK_ENV_NAMES})")
# Вимикає дозволи або хуки дочірнього агента: нічим не страхується.
AGENT_BYPASS = re.compile(rf"\bclaude(?:\.exe)?\b{_SEGMENT}(?:--dangerously-skip-permissions|--allow-dangerously-skip-permissions|"
                          r"--bare\b|--permission-mode[=\s]+bypassPermissions)")
# Законні дії людини, але не моделі мовчки: нова поверхня інструментів чи хуків. Вирішує людина.
AGENT_CONFIG = re.compile(rf"\bclaude(?:\.exe)?\s+(?:mcp\s+(?:add\S*|remove)|plugin\s+(?:install|i|enable|marketplace\s+add))\b|"
                          rf"(?i:{_WRITERS}{_SEGMENT}(?:\S*[/\\])?(?:\.claude[/\\]+settings[\w.]*\.json|\.mcp\.json))")
PRAGMA_TAMPER = re.compile(rf"(?i:\bsed\s+-i{_SEGMENT}secret-scan|\b(?:echo|printf|Add-Content|Set-Content){_SEGMENT}secret-scan{_SEGMENT}(?:>|\S))")
SEARCH_RUNS_PROGRAM = re.compile(rf"\brg\b{_SEGMENT}\s--pre(?:[=\s]|$)")
# Історія пишеться повз `git commit`: pre-commit не спрацьовує, а вмісту в тексті команди немає.
HISTORY_PLUMBING = re.compile(
    rf"\bgit\b{_SEGMENT}\b(?:fast-import|commit-tree|update-ref)\b|"
    rf"\bgit\b{_SEGMENT}\bnotes\s+(?:--ref\S*\s+\S*\s*)?(?:add|append|copy|edit|merge|remove|prune)\b|"
    rf"\bgit\b{_SEGMENT}\bam\b(?!{_SEGMENT}--(?:abort|skip|show-current-patch|quit))|"
    rf"\bgh\b{_SEGMENT}\brepo\s+create\b{_SEGMENT}\s--push\b|"
    rf"\bgh\s+api\b(?={_SEGMENT}(?:-X\s*|--method[\s=])(?:PUT|POST|PATCH))(?={_SEGMENT}/(?:contents|git)/)")
# Вихідний канал усередині git (обхід К9-05): код іде третій стороні листом без жодного push,
# тому гейт коміту/пушу його не бачить. Лист третій стороні вирішує людина. `git -c … send-email`
# і `git-send-email` ловляться тим самим шаблоном; довідку (`git help send-email`, `--help`) не чіпаємо.
GIT_OUTBOUND = re.compile(rf"\bgit\b(?!\s+help\s){_SEGMENT}\b(?:send-email|imap-send)\b(?!\s+--help\b)", re.I)
SKIP_HOOKS_ENV = re.compile(r"\b(?:HUSKY\s*=\s*0|HUSKY_SKIP_HOOKS\s*=|SKIP\s*=\S*|LEFTHOOK\s*=\s*0|"
                            r"KEEL_HOME\s*=|HOME\s*=|USERPROFILE\s*=)")
REPO_OVERRIDE = re.compile(r"\bgit\s+(?:-\S+(?:\s+\S+)?\s+)*?--(?:git-dir|work-tree)\b|"
                           r"\bGIT_(?:DIR|WORK_TREE|INDEX_FILE|COMMON_DIR|OBJECT_DIRECTORY)\s*=")
_CD = re.compile(r"""(?:^|[;&|('"\s])(?:cd|pushd|Set-Location|sl)\s+("[^"]+"|'[^']+'|[^\s;&|'"]+)\s*(?:&&|\|\||;|\n)""", re.I)
_GIT_C = re.compile(r"""\bgit(?:\.exe)?\s+-C\s+("[^"]+"|'[^']+'|\S+)""")
SHELL_TOOLS = {"Bash", "PowerShell"}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
# Термінали й запис файлів через MCP: той самий ризик, що й у Bash чи Write. Інші MCP хук не бачить.
MCP_SHELL = re.compile(r"mcp__.*__(?:run_in_terminal|start_process|execute_command|run_command)")
MCP_REPL = re.compile(r"mcp__.*__interact_with_process")
MCP_WRITE = re.compile(r"mcp__.*__(?:write_file|edit_block|edit_file)")
MCP_MOVE = re.compile(r"mcp__.*__move_file")


class Blocked(Exception):
    pass


class AskHuman(Exception):
    """Дія законна, але рішення за людиною: хук віддає `ask`, а не блок."""


def _report(findings: list[secretscan.Finding], where: str) -> str:
    lines = [f"Keel заблокував дію: схоже на секрет ({where})."]
    for item in findings[:10]:
        lines.append(f"  {item.file}:{item.line} {item.type} {item.preview}")
    lines.append("Винеси значення в змінну середовища або файл поза git.")
    return "\n".join(lines)


def _new_content(name: str, tool_input: dict) -> str:
    if name == "Write":
        return tool_input.get("content", "")
    if name == "Edit":
        return tool_input.get("new_string", "")
    if name == "MultiEdit":
        return "\n".join(str(e.get("new_string", "")) for e in tool_input.get("edits") or [])
    return tool_input.get("new_source", "")


def _protected(path: Path, vault: Vault) -> bool:
    resolved = path.resolve()
    if resolved == (vault.root / "inbox" / "DECISIONS.md").resolve():
        return True
    try:
        resolved.relative_to(vault.state.resolve())
        return True
    except ValueError:
        return False


def _is_git_control_file(path: Path) -> bool:
    """Запис у .git/hooks чи .git/config вимикає другий рубіж без жодної git-команди."""
    parts = [p.rstrip(". ").casefold() for p in path.parts]
    for index, part in enumerate(parts[:-1]):
        if re.fullmatch(r"\.git|git~\d", part) and parts[index + 1] in {"hooks", "config"}:
            return True
    return False


def _is_agent_config(path: Path) -> bool:
    parts = [p.casefold() for p in path.parts]
    return parts[-1:] == [".mcp.json"] or (len(parts) >= 2 and parts[-2] == ".claude" and re.fullmatch(r"settings[\w.]*\.json", parts[-1]) is not None)


def check_write(name: str, tool_input: dict, vault: Vault) -> None:
    target = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
    if target and _protected(Path(target), vault):
        raise Blocked("Стан Keel змінює лише код рушія, а не модель. "
                      "Рішення приймає людина через /keel:decide.")
    if target and _is_git_control_file(Path(target)):
        raise Blocked("Keel заблокував запис у .git/hooks або .git/config. Це робить людина.")
    if target and _is_agent_config(Path(target)):
        raise AskHuman("Зміна конфігу агента (хуки, дозволи, MCP): вирішує людина.")
    found = secretscan.scan_text(_new_content(name, tool_input), target or "<new>")
    if found and not (target and secretscan.is_git_ignored(Path(target))):
        raise Blocked(_report(found, target))


def _strip_heredocs(command: str) -> str:
    """Текст heredoc це дані, окрім випадку, коли його читає інтерпретатор (`bash <<EOF`)."""
    def replace(match: re.Match) -> str:
        line = command[command.rfind("\n", 0, match.start()) + 1:match.start()]
        return match.group(0) if _FEEDS_HEREDOC.search(line) else " "
    return _HEREDOC.sub(replace, command)


def _shell_words(command: str, powershell: bool) -> list[str] | None:
    """Розбір за правилами оболонки: `g""it` це git, а `"a b"` один аргумент. None: незакриті лапки."""
    escape = "`" if powershell else "\\"
    words: list[str] = []
    current, started, index, quote = [], False, 0, ""

    def flush() -> None:
        nonlocal current, started
        if started:
            words.append("".join(current))
        current, started = [], False

    while index < len(command):
        char = command[index]
        following = command[index + 1] if index + 1 < len(command) else ""
        if quote:
            if char == quote:
                quote = ""
            elif char == escape and quote == '"' and following:
                current.append(following)
                index += 1
            else:
                current.append(char)
        elif char in "\"'":
            quote, started = char, True
        elif char == escape and following:
            if following != "\n":
                current.append(following)
                started = True
            index += 1
        elif char == "&" and (following == ">" or (current and current[-1] == ">")):
            current.append(char)  # перенаправлення `2>&1`, а не кінець команди
        elif char in ";&|\n":
            flush()
            words.append(char)
        elif char.isspace():
            flush()
        else:
            current.append(char)
            started = True
        index += 1
    if quote:
        return None
    flush()
    return words


def _decode_ansi_c(command: str) -> str:
    """`$'\\x67it'` оболонка розгортає в git ще до запуску."""
    def decode(match: re.Match) -> str:
        try:
            return "'" + match.group(1).encode("latin-1", "backslashreplace").decode("unicode_escape") + "'"
        except ValueError:
            return match.group(0)
    return _ANSI_C.sub(decode, command)


def _unglob(word: str) -> str:
    """`/usr/bin/g?t`, `gi[t]`, `g{i,x}t`: якщо шаблон може дати git, вважаємо, що дасть."""
    base = re.split(r"[/\\]", word)[-1].strip("()")
    if not re.search(r"[?*\[{]", base) or not re.search(r"\w", base) or base.startswith(("$", "-")):
        return word
    brace = re.fullmatch(r"(.*)\{([^{}]*,[^{}]*)\}(.*)", base)
    variants = [brace.group(1) + part + brace.group(3) for part in brace.group(2).split(",")] if brace else [base]
    for name in _GLOBBED_NAMES:
        if any(fnmatch.fnmatchcase(name, pattern) for pattern in variants):
            return name
    return word


def _flatten(words: list[str]) -> str:
    """Лапки зникають. Багатослівний аргумент і текст повідомлення коміту командою не вважаються."""
    result: list[str] = []
    in_commit, message_next = False, False
    for word in words:
        if word in {";", "&", "|", "\n"}:
            in_commit, message_next = False, False
            result.append(word)
            continue
        if message_next:
            message_next = False
            result.append('""')
            continue
        if in_commit:
            if word in {"--message", "--file", "-F"}:
                message_next = True
            elif word.startswith(("--message=", "--file=")):
                word = '""'
            else:
                cluster = re.fullmatch(r"-([a-zA-Z]*?)m(.*)", word, re.S)
                if cluster:
                    message_next = not cluster.group(2)
                    word = f"-{cluster.group(1)}m"
        word = _unglob(word)
        if word == "commit":
            in_commit = True
        keep = not re.search(r"\s", word) or word.startswith("$(") or _KEEP_QUOTED.search(word)
        result.append(word if keep else '""')
    return " ".join(result)


def _expand(text: str) -> str:
    """Значення змінної чи підстановки невідоме, тому вважаємо, що там може бути git."""
    return _EXPANSION.sub("git", text)


class ShellView:
    """Без dataclasses свідомо: їхній імпорт тягне inspect і коштує ~50 мс на кожну shell-команду."""
    __slots__ = ("text", "indirect")

    def __init__(self, text: str, indirect: bool):
        self.text = text
        self.indirect = indirect  # команду обгорнуто або підставлено: бачимо її лише приблизно

    @property
    def wants_commit(self) -> bool:
        if self.indirect:
            return bool(re.search(r"\bgit\b", self.text) and re.search(r"\bcommit\b", self.text))
        return bool(GIT_COMMIT.search(self.text))

    @property
    def wants_push(self) -> bool:
        if self.indirect:
            return bool(re.search(r"\bgit\b", self.text) and re.search(r"\bpush\b", self.text))
        return bool(GIT_PUSH.search(self.text))


def view_of(command: str, powershell: bool = False, indirect: bool = False) -> ShellView:
    command = _decode_ansi_c(command)
    words = _shell_words(_strip_heredocs(command), powershell)
    flat = _flatten(words) if words is not None else ""
    if indirect or words is None or INDIRECT.search(flat):
        plain = command.replace("`", "") if powershell else command
        # `g\\it` це git, а `.git\\hooks` це шлях: потрібні обидва прочитання зворотного скісного.
        text = re.sub(r"[\"'\\^]", "", plain) + "\n" + re.sub(r"[\"'^]", "", plain)
        return ShellView(re.sub(r"[,()\[\]{}]", " ", _expand(text)).replace("`", " "), True)
    expanded = _expand(flat)
    return ShellView(expanded, expanded != flat)


def _has_pathspec(text: str) -> bool:
    """`git commit файл` комітить мимо індексу, тож сканування staged його не побачить."""
    for match in COMMIT_ARGS.finditer(text):
        for word in match.group(1).split():
            if word != '""' and not word.startswith("-") and not re.match(r"\d*[<>]", word):
                return True
            if word in {"--include", "-i", "--only", "-o"} or re.fullmatch(r"-[a-zA-Z]*[io]", word):
                return True
    return False


def _resolve_repo(command: str, cwd: Path) -> Path:
    """Сканувати треба той репозиторій, у якому станеться коміт. Невідомий шлях означає блок."""
    plain = re.sub(r"\"\"|''", "", command)
    match = _GIT_C.search(plain)
    if not match:
        action = re.search(r"\b(?:commit|push)\b", plain)
        limit = action.start() if action else len(plain)
        matches = [m for m in _CD.finditer(plain) if m.start() < limit]
        match = matches[-1] if matches else None
    if not match:
        return cwd
    target = match.group(1).strip("\"'")
    if re.search(r"[$%`]", target):
        raise Blocked(f"Keel не може визначити репозиторій зі шляху {target}: вкажи літеральний шлях.")
    return cwd / Path(target).expanduser()


def check_shell(raw_command: str, cwd: Path, powershell: bool = False, indirect: bool = False) -> None:
    found = [f for f in secretscan.scan_text(raw_command, "<команда>")
             if f.type not in secretscan.ASSIGN_TYPES]
    if found:
        raise Blocked(_report(found, "текст команди"))
    view = view_of(raw_command, powershell, indirect)
    text = view.text
    if OPAQUE.search(text):
        raise Blocked("Keel не може прочитати закодовану команду. Напиши її відкрито або спитай людину.")
    if AGENT_BYPASS.search(text):
        raise Blocked("Keel заблокував запуск агента без дозволів чи хуків. Це робить людина у своєму терміналі.")
    if PRAGMA_TAMPER.search(text):
        raise Blocked("Keel заблокував дописування прагми `secret-scan: ignore` командою. Фікстуру позначає людина.")
    if SEARCH_RUNS_PROGRAM.search(text):
        raise Blocked("Keel заблокував `rg --pre`: пошук запускав би програму. Спитай людину.")
    if AGENT_CONFIG.search(text):
        raise AskHuman("Нова поверхня інструментів чи зміна конфігу агента: вирішує людина.")
    tampering = [m for m in _CONFIG_TAMPER.finditer(text) if not _CONFIG_READ.search(m.group(0))]
    if tampering or HOOK_FILES.search(text) or ENV_TAMPER.search(text):
        raise Blocked("Keel заблокував зміну git-хуків чи конфігурації, якою їх можна обійти. Це робить людина.")
    if HISTORY_PLUMBING.search(text):
        raise Blocked("Keel заблокував запис історії повз `git commit`: перевірити вміст неможливо. Це робить людина.")
    if NO_VERIFY.search(text):
        raise Blocked("Keel заблокував --no-verify. Якщо гейт хибить, полагодь гейт або спитай людину.")
    if GIT_OUTBOUND.search(text):
        raise Blocked("Keel заблокував `git send-email`/`git imap-send`: це надсилання коду третій стороні "
                      "повз push і перевірку секретів. Це робить людина.")
    if GIT_WRAPPER_DEF.search(text) and re.search(r"\b(?:commit|push)\b", text):
        raise Blocked("Keel не бачить команду за alias чи функцією над git. Напиши її прямо.")
    wants_commit, wants_push = view.wants_commit, view.wants_push
    if not (wants_commit or wants_push):
        return
    if SKIP_HOOKS_ENV.search(text):
        raise Blocked("Keel заблокував вимкнення хуків через змінну середовища.")
    if REPO_OVERRIDE.search(text):
        raise Blocked("Keel заблокував коміт в інший git-каталог чи індекс: перевірка дивилась би не туди.")
    cwd = _resolve_repo(raw_command, cwd)
    if wants_commit:
        whole_tree = (view.indirect or GIT_ADD.search(text) or COMMIT_ALL.search(text) or _has_pathspec(text))
        found = secretscan.scan_worktree_changes(cwd) if whole_tree else secretscan.scan_staged(cwd)
        if found:
            raise Blocked(_report(found, "git commit"))
    if wants_push:
        found = secretscan.scan_unpushed(cwd)
        if found:
            raise Blocked(_report(found, "git push"))


class ShellRequest:
    __slots__ = ("command", "powershell", "indirect", "cwd")

    def __init__(self, command: str, powershell: bool, indirect: bool, cwd: str):
        self.command, self.powershell, self.cwd = command, powershell, cwd
        self.indirect = indirect  # введення в REPL це код, а не команда оболонки


def _shell_request(name: str, tool_input: dict, cwd: str) -> ShellRequest | None:
    if name in SHELL_TOOLS:
        return ShellRequest(tool_input.get("command", ""), name == "PowerShell", False, cwd)
    if MCP_REPL.fullmatch(name):
        return ShellRequest(str(tool_input.get("input", "")), False, True, cwd)
    if MCP_SHELL.fullmatch(name):
        # На Windows такі інструменти за замовчуванням запускають PowerShell.
        shell = str(tool_input.get("shell", ""))
        powershell = "powershell" in shell.lower() or "pwsh" in shell.lower() or (os.name == "nt" and not shell)
        return ShellRequest(str(tool_input.get("command", "")), powershell, False, str(tool_input.get("cwd") or cwd))
    return None


def _check_move(tool_input: dict, vault: Vault) -> None:
    for key in ("source", "destination"):
        target = Path(str(tool_input.get(key) or ""))
        if _is_git_control_file(target) or _protected(target, vault):
            raise Blocked("Keel заблокував переміщення git-хуків, конфігу або стану Keel. Це робить людина.")


def decide(payload: dict, vault: Vault) -> None:
    name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input") or {}
    if name in WRITE_TOOLS:
        check_write(name, tool_input, vault)
    elif MCP_WRITE.fullmatch(name):
        check_write("Write", {"file_path": tool_input.get("path") or tool_input.get("file_path") or "",
                              "content": str(tool_input.get("content") or tool_input.get("new_string") or "")}, vault)
    elif MCP_MOVE.fullmatch(name):
        _check_move(tool_input, vault)
    else:
        request = _shell_request(name, tool_input, payload.get("cwd") or ".")
        if request:
            check_shell(request.command, Path(request.cwd), request.powershell, request.indirect)


def must_fail_closed(payload: dict) -> bool:
    name = payload.get("tool_name", "")
    if name in WRITE_TOOLS or MCP_WRITE.fullmatch(name) or MCP_MOVE.fullmatch(name):
        return True
    request = _shell_request(name, payload.get("tool_input") or {}, ".")
    if request is None:
        return False
    try:
        view = view_of(request.command, request.powershell, request.indirect)
    except Exception:  # noqa: BLE001 - розбір упав, отже намір невідомий
        return "git" in request.command.lower()
    return (view.wants_commit or view.wants_push or bool(HISTORY_PLUMBING.search(view.text))
            or bool(GIT_OUTBOUND.search(view.text)))


def main(stdin=None, vault: Vault | None = None) -> int:
    try:
        payload = json.load(stdin or sys.stdin)
    except Exception as exc:  # noqa: BLE001
        print(f"Keel: не вдалося прочитати запит хука: {exc}", file=sys.stderr)
        return 2
    try:
        decide(payload, vault or Vault.default())
        return 0
    except Blocked as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except AskHuman as exc:
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                                 "permissionDecisionReason": str(exc)}}, ensure_ascii=False))
        return 0
    except Exception as exc:  # noqa: BLE001 - збій гейта не повинен тихо пропускати запис
        if must_fail_closed(payload):
            print(f"Keel: збій перевірки секретів, дію зупинено: {exc}. "
                  "Діагностика: /keel:doctor. Вимкнути може лише людина через /plugin.",
                  file=sys.stderr)
            return 2
        print(f"Keel: попередження, збій перевірки: {exc}", file=sys.stderr)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
