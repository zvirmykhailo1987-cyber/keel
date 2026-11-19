# Keel

[![ci](https://github.com/zvirmykhailo1987-cyber/keel/actions/workflows/ci.yml/badge.svg)](https://github.com/zvirmykhailo1987-cyber/keel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**A Claude Code plugin that lets an AI agent work in your repository without leaking secrets or rewriting history behind your back.**

Keel is a "second brain" for developers: a layered secret gate around every write, shell command and git ref update, a dependency radar (OSV, registries, end-of-life), a personal knowledge vault, and a tiered autopilot whose most dangerous tier has *no executor in the code at all*.

> **Status: PRELIMINARY, beta.** The engine self-tests run in CI on Ubuntu, Windows and macOS with Python 3.11 and 3.13. Real quota consumption and usefulness on large codebases have not been measured yet. Runtime messages, agent prompts and skills are written in Ukrainian, the author's working language; code, manifests and this documentation are in English.

### What this repository is, and what it is not

Keel is the portable, self-contained layer of the harness I use every day: the guards, the dependency radar and the vault that any developer can install without my help. It is deliberately a starting point.

The full harness behind my own delivery work stays private: the skill library and task agents, the registry of failure patterns learned from retrospectives, the release gates per project type, and the autopilot that changes a skill only through a branch, self-tests, an old-versus-new behaviour eval and a trial period with automatic revert. Fitting that to a team's repositories, constraints and NDA is the part that cannot be packaged; I do it as part of an engagement. Contact: [mykhailo-zvir.pages.dev](https://mykhailo-zvir.pages.dev).

## Why

An agent with a shell can commit a token, push it, or move a branch with `git commit-tree` + `git update-ref` so that no `pre-commit` hook ever runs. Pattern-matching the command text alone cannot answer "is this a commit?" — there are endless spellings (`g?t`, `$'\x67it'`, `sh -c`, MCP terminals, `gh api`). Keel therefore stacks independent gates and treats each one as a safety net, not a boundary:

| Layer | Runs on | Catches | Can the agent switch it off? |
|---|---|---|---|
| 1. `PreToolUse` hook (`guard.py`) | every Bash / PowerShell / Write / Edit / MultiEdit / NotebookEdit and file-writing or terminal MCP tool | secrets in the content or command text; `--no-verify` in any spelling; hook and git-config tampering; history plumbing (`fast-import`, `commit-tree`, `update-ref`, `am`); `gh api` writes; `git apply` patches before a commit | No: changes to `.git/hooks`, git config (repo, worktree, global, XDG) and Keel state are blocked |
| 2. git `pre-commit` | every `git commit`, from any tool or terminal | secrets in staged changes | `--no-verify` is blocked at layer 1 |
| 3. git `reference-transaction` | **every** ref update: commit, `commit-tree` + `update-ref`, `fast-import`, `am`, rebase | secrets in commits that are new to the repository | Not by `--no-verify`. It is installed even when `core.hooksPath` points to a hook manager's directory |
| 4. Server (your side) | push | everything above, authoritatively | — enable GitHub push protection or gitleaks in CI |

The scanner looks at 19 unambiguous key shapes plus assignment heuristics, and also at values **split across string literals** (`"AKIA" + "…"`, implicit concatenation, also across line breaks), **encoded** as base64, base64url, hex or `\x..` escapes, inside **binary, UTF-16 or unlisted files**, and past the first 4000 characters of a minified line. It runs git with `--no-ext-diff --no-textconv --text` and a scrubbed environment, so a hostile repository config cannot blind it.

Every bypass technique we know of, with its status and its paired regression test, is listed in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Install

Requirements: Claude Code, Python 3.11+, git 2.28+ (on Windows, Git for Windows, which also provides `sh`). No third-party Python packages.

From GitHub:

```
/plugin marketplace add zvirmykhailo1987-cyber/keel
/plugin install keel@keel-marketplace
```

From a local clone or the release ZIP:

```
/plugin marketplace add /path/to/keel
/plugin install keel@keel-marketplace
```

Restart the session, then run `/keel:setup` once and `/keel:init-project` inside each repository you want to protect. `init-project` shows a plan (permissions, hooks, files) and changes nothing until you approve `--apply`.

## What is inside

| Part | What it does |
|---|---|
| **Guard** | The layered secret and history gate described above. Fails closed: any crash while checking a write or a commit blocks it. |
| **Radar** | Lockfiles → vulnerabilities (OSV), outdated versions (npm, PyPI, crates, Go, Maven, Packagist, NuGet, RubyGems), end-of-life (endoflife.date). No LLM, no keys. A source that did not answer is reported as "not checked", never as "clean". |
| **Brain** | Personal vault (Markdown + git, opens in Obsidian) and per-project memory in `.keel/`. Survives plugin updates. |
| **Growth** | Pitfall registry, retros, lessons, skill overlays with a 14-day trial, spaced-repetition skill map. |
| **Autopilot** | The model only *proposes* actions as JSON; deterministic code validates and executes them by tier. |
| **OSINT** | Library and vendor checks. A fact is accepted only with a verbatim quote found on the cited page. |
| **Skills and agents** | 14 skills (review, debugging, testing, security, architecture, migrations, deploy/CI, performance, observability, frontend, LLM apps, mobile, OSINT, self-improvement), 12 agents, 11 stack profiles. |

### Autopilot tiers

| Tier | Actions | Who executes |
|---|---|---|
| 0 | Reports, scans | automatic |
| 1 | Notes, lessons, ADR drafts in the vault, each with `undo` | automatic |
| 2 | Local `keel/*` branch with a patch-level dependency bump (npm, cargo, go), only if enabled in `.keel/project.toml` | automatic, never merged |
| 3 | Push to main, merge, deploy, publish, production migrations, money, secrets, outbound messages | **human only**: there is no executor for it in the code |

Off by default: background LLM runs, the scheduler, dependency autoupdates, and running the tests of an updated dependency (that executes third-party code).

## Known limits

- **The gate is a safety net, not a boundary.** It reads command text and file content. A script that is already on disk, or a secret assembled at runtime from variables, is invisible to it until it reaches layer 2 or 3; values split into separate variables, `"".join([...])`, `\u` escapes or misaligned encodings (a one-character prefix before base64, odd-length hex) are not reassembled. The authoritative boundary is server-side push protection.
- Layer 1 sees only tools whose names it matches (shell, terminal and file-writing MCP tools with conventional names). An MCP server with an unusual tool name, or a sub-agent outside this session, is covered by layers 2–4 only.
- Layer 3 needs git 2.28+. If a repository already has its *own* `pre-commit` or `reference-transaction`, Keel leaves it alone and `init-project` says what to add; with `core.hooksPath` set inside the repository, Keel adds only `reference-transaction` to that directory (listed in `.git/info/exclude`, so it is never committed to the team repo, and protected from the agent like `.git/hooks`) and leaves `pre-commit` to the hook manager; a `core.hooksPath` outside the repository is a shared directory, so Keel installs nothing there and says what to add. If `core.hooksPath` is changed later by a human, `/keel:doctor` reports the project as unprotected.
- A human can deliberately skip layers 2–3 in their own terminal: `KEEL_ALLOW_SECRET=1 git commit --no-verify`. The agent cannot.
- `secret-scan: ignore` silences assignment heuristics (not key shapes). Adding the pragma through a tool asks the human.
- Changing agent configuration (`.claude/settings*.json`, `.mcp.json`, `claude mcp add`, `claude plugin install`) and publishing via `gh gist` / `gh release` are not blocked but escalated to the human. Starting a child agent without permissions or hooks is blocked.
- Background runs are split: the one that browses the web has no file tools, the one that reads code has no network. That removes the obvious exfiltration channel, not prompt injection as such.
- Stack profiles are verified on small fixtures (detection and commands), not as expertise in each language. Swift and C/C++ are `beta`.

## Development

```
sh src/plugin/hooks/run.sh -m keel selftest      # engine self-tests (stdlib unittest)
python tests/e2e_local.py                        # end-to-end on the built dist, live network, no LLM
python tests/e2e_claude.py                       # live Claude Code session with an isolated profile (uses a little quota)
KEEL_DENYLIST=/path/to/denylist.txt python build/build_dist.py   # release ZIP + dist/BUILD-REPORT.md
```

The self-tests run git with an empty global and system config, so the results do not depend on the machine. The build refuses to run without a private denylist of personal markers and checks both the distribution and every file tracked in this repository against it; the report records counts and SHA-256 of every shipped file.

Layout: `src/plugin/` is the plugin itself (hooks, `engine/keel` in pure Python, skills, agents, commands, data), `.claude-plugin/marketplace.json` makes the repository installable, `build/` produces the release ZIP, `tests/` holds the end-to-end runs, `docs/` the threat model and the original research.

## Diagnostics and removal

`/keel:doctor` reports the measured state, not the configured one: when each part last actually ran, and whether each connected repository still has its git hooks where git will execute them. The report contains no code and no secrets.

`/keel:uninstall` removes the scheduler task and Keel's git hooks. The vault stays yours.

## License

[MIT](LICENSE) © 2026 Mykhailo Zvir. Keep the copyright notice in copies and derived work.
