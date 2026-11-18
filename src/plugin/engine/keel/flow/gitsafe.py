"""Єдиний шлях рушія до git. Білий список підкоманд: push і merge не існують як можливість.
Тест AST перевіряє, що інших викликів git у рушії немає."""
from __future__ import annotations

import subprocess
from pathlib import Path

ALLOWED = {"init", "add", "commit", "status", "rev-parse", "worktree", "branch", "log", "diff", "show",
           "revert", "symbolic-ref", "ls-files", "config"}
FORBIDDEN_ARGS = {"--force", "-f", "--no-verify", "-D", "--global", "--system"}
PROTECTED_BRANCHES = {"main", "master", "develop", "production", "prod", "release", "trunk"}
BRANCH_PREFIX = "keel/"


class GitRefused(RuntimeError):
    pass


def git_safe(args: list[str], cwd: Path, timeout: float = 120, check: bool = True) -> str:
    if not args or args[0] not in ALLOWED:
        raise GitRefused(f"підкоманда не дозволена: {args[:1]}")
    if args[0] in {"worktree", "branch"} and set(args) & {"--force", "-f", "-D"}:
        raise GitRefused("примусові дії не дозволені")
    if args[0] != "worktree" and set(args) & FORBIDDEN_ARGS:
        raise GitRefused(f"заборонений аргумент: {sorted(set(args) & FORBIDDEN_ARGS)}")
    done = subprocess.run(["git", "-c", "core.quotepath=false", "-c", "core.autocrlf=false", *args],
                          cwd=cwd, capture_output=True, timeout=timeout)
    out = done.stdout.decode("utf-8", errors="replace")
    if check and done.returncode != 0:
        raise RuntimeError(f"git {args[0]}: {done.stderr.decode('utf-8', 'replace')[:300]}")
    return out


def commit_all(repo: Path, message: str) -> str | None:
    """Коміт усього в репо vault або worktree гілки keel/*. Повертає SHA або None, якщо змін немає."""
    git_safe(["add", "-A"], repo)
    if not git_safe(["status", "--porcelain"], repo).strip():
        return None
    _commit(repo, message)
    return git_safe(["rev-parse", "HEAD"], repo).strip()


def discard_keel_branch(repo: Path, branch: str, worktree: Path) -> None:
    """Прибирання власної невдалої спроби. Єдине примусове видалення, і лише для keel/*:
    `branch -d` не чіпає незлиту гілку, а `worktree remove` брудну теку, тоді наступний запуск застрягне."""
    assert_branch_allowed(branch)
    for args in (["worktree", "remove", "--force", str(worktree)], ["worktree", "prune"], ["branch", "-D", branch]):
        subprocess.run(["git", *args], cwd=repo, capture_output=True, timeout=120)


def _commit(repo: Path, message: str) -> None:
    done = subprocess.run(["git", "-c", "user.name=Keel", "-c", "user.email=keel@localhost", "-c",
                           "core.hooksPath=/dev/null", "commit", "-q", "-m", message],
                          cwd=repo, capture_output=True, timeout=120)
    if done.returncode != 0:
        raise RuntimeError(f"git commit: {done.stderr.decode('utf-8', 'replace')[:300]}")


def ensure_repo(path: Path) -> None:
    if not (path / ".git").exists():
        git_safe(["init", "-q", "-b", "main"], path)


def assert_branch_allowed(branch: str) -> None:
    if not branch.startswith(BRANCH_PREFIX) or branch.split("/")[-1] in PROTECTED_BRANCHES:
        raise GitRefused(f"гілка поза {BRANCH_PREFIX}*: {branch}")
