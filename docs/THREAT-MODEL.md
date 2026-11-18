# Keel threat model and bypass coverage

Scope: an AI agent working inside a developer's repository through Claude Code. The assets are
credentials (keys, tokens, passwords) and the integrity of git history. The adversary is the agent
itself acting on a mistaken or injected instruction: it can choose any spelling of a command, any
available tool, and any encoding of content. It cannot act in the human's own terminal.

The original research (in Ukrainian, with sources and verification dates) is
[BYPASS-RESEARCH.md](BYPASS-RESEARCH.md). Every row below has at least one *paired* regression test:
the bypass is blocked **and** the ordinary command next to it still passes (a gate that gets in the
way is the gate that gets disabled). Test names refer to `src/plugin/engine/keel_tests/`.

Layers: **L1** `PreToolUse` hook (`guard.py`) · **L2** git `pre-commit` · **L3** git
`reference-transaction` · **L4** server-side push protection (outside Keel).

| # | Technique | Status | Where it is stopped | Tests |
|---|---|---|---|---|
| 1 | `git commit-tree` + `git update-ref` (history without `git commit`) | Closed | L1 blocks the plumbing verbs; L3 rejects the ref update if the new commit contains a secret | `test_guard.GuardCase.test_history_written_without_commit_command`, `test_growth.TestPreCommitReal.test_plumbing_cannot_move_branch_to_secret`, same in `TestHooksPathReal` |
| 2 | `git fast-import` | Closed | L1 + L3 | `test_history_written_without_commit_command`, `TestPreCommitReal.test_fast_import_cannot_create_branch_with_secret` |
| 3 | `git am` / `git apply` | Closed | L1 blocks `am`; for `git apply … && git commit` L1 reads the patch itself (stdin or missing patch is blocked); L3 covers `am` | `test_history_written_without_commit_command`, `TestBypassResearch.test_git_apply_then_commit_reads_the_patch` |
| 4 | `gh api` / `gh repo create --push` / gists / releases | Closed for content-writing endpoints | L1: `contents`, `git/*`, `releases`, `gists` with PUT/POST/PATCH **or with fields and no method** (gh defaults to POST), GraphQL `createCommitOnBranch`/`createRef`/`updateRef(s)`/`mergeBranch`; `gh gist create`, `gh release create/upload` are escalated to the human | `test_history_written_without_commit_command`, `TestBypassResearch.test_gh_api_writes_without_explicit_method`, `test_gh_publish_goes_to_human` |
| 5 | Scanner's own `git diff` runs `diff.external` / textconv | Closed | Scanner uses `--no-ext-diff --no-textconv --text`; L1 blocks setting them | `test_scanner_is_not_blinded_by_repo_config`, `test_scanner_tampering_blocked` |
| 6 | `GIT_EXTERNAL_DIFF`, `GIT_CONFIG_*` inherited by the scanner | Closed | Scanner scrubs the environment; L1 blocks setting them | same |
| 7 | `core.fsmonitor` command executed during the scan | Closed | Scanner forces `core.fsmonitor=false`; L1 blocks setting it | `test_scanner_tampering_blocked` |
| 8 | MCP terminals (`run_in_terminal`, `start_process`, `interact_with_process`, …) | Closed for conventional tool names | L1 matcher covers them; REPL input is read as code; L2–L3 cover everything else | `test_mcp_terminals_are_covered`, `test_mcp_terminal_uses_its_own_cwd`, `test_repl_input_is_read_as_code`, `test_matcher_selects_exactly_the_risky_mcp_tools` |
| 9 | MCP file writes bypassing `check_write` | Closed for conventional tool names | `write_file`, `edit_block`, `edit_file`, `write_pdf`, `create_file`, `update_file`, `append_file`, `move_file`; **every** text field is scanned, not just `content` | `test_mcp_write_tools_are_covered`, `TestBypassResearch.test_mcp_write_scans_every_field` |
| 10 | `MultiEdit` | Closed | L1 | `test_multiedit_is_scanned` |
| 11 | Secret split into concatenated literals | Closed for adjacent literals within 4 lines | Scanner joins `+`, `.`, `..`, `&` and implicit concatenation, in files and in diff blocks | `TestBypassResearch.test_split_secret_in_write`, `test_split_secret_in_commit` |
| 12 | Secret encoded (base64, hex) | Closed for base64, base64url, hex, `\x..` | Scanner decodes candidate tokens and looks for the same key shapes | `TestBypassResearch.test_encoded_secret` |
| 13 | Secret in a binary or unlisted file | Closed | Staged diff with `--text`; untracked files of any suffix; long lines scanned in overlapping windows | `test_scanner_sees_files_marked_binary`, `TestBypassResearch.test_binary_and_unlisted_files` |
| 14 | `secret-scan: ignore` pragma | Partly closed (by design) | The pragma never silences key shapes; adding it via shell is blocked, via Write/Edit/MCP is escalated to the human | `test_shape_token_survives_pragma_and_comment`, `test_second_wave_blocked`, `TestBypassResearch.test_new_pragma_goes_to_human` |
| 15 | Values tuned below the assignment heuristics (length < 12, entropy < 3.0, placeholder prefix) | Residual risk | Key shapes still match; generic assignments may slip | `test_real_non_secrets_are_not_flagged` documents the trade-off |
| 16 | `git` spelled through globs, substitution, escapes (`g?t`, `$'\x67it'`, `$(…)`, `g^it`) | Closed | L1 unglobs and expands; L2–L3 do not depend on spelling at all | `test_shell_expansion_of_git_name`, `test_indirect_commit_scans_worktree` |
| 17 | `core.hooksPath` that switches off L2–L3 | Closed for the agent | L1 blocks it in repo, worktree, global and XDG config, `-c`, `--config-env` and env vars; when a hook manager already set it, `reference-transaction` is installed into that directory; `/keel:doctor` flags a repository whose hooks git will no longer run | `test_hook_tampering_blocked`, `TestBypassResearch.test_git_config_outside_repo_protected`, `test_growth.TestProject.test_husky_path_respected`, `test_doctor_sees_hooks_disabled_by_hooks_path`, `TestHooksPathReal` |
| 17b | Push to an arbitrary remote | Partly closed | Every push is scanned for secrets in unpushed commits; credentials in URLs are caught; pushing to a foreign remote as such is not blocked | `test_push_scans_unpushed_commits`, `test_push_scans_other_branches` |
| 18 | Claude Code deny-rule degradation after 50+ subcommands | Not applicable to L1 | The hook sees the whole command before execution | `TestBypassResearch.test_padding_does_not_hide_commit` |
| 19 | Claude Code command-parsing CVEs (`$IFS`, `find`, `sed`+`echo`, `cd`) | Out of scope | They bypass Claude Code's permission prompts, not Keel's hook; keep Claude Code updated | — |

## Known limits (what Keel does not claim)

- **"Is this a commit?" is undecidable from command text.** L1 is an early, best-effort gate. L2–L3
  are git-native and spelling-independent; L4 is the only authoritative boundary.
- **Runtime assembly.** A secret built from separate variables, read from a file at run time, or split
  across more than four lines is not reassembled by the scanner. Other encodings (compression,
  ROT13, double or custom encodings) are not decoded. L4 is the answer.
- **Unconventionally named MCP tools** and agents outside this Claude Code session are invisible to L1;
  only L2–L4 apply.
- **A human can override** L2–L3 in their own terminal (`KEEL_ALLOW_SECRET=1 git commit --no-verify`);
  the override is loud. The agent cannot set the variable or the flag.
- **A pre-existing foreign hook** of the same name is never overwritten; `init-project` reports it and
  the human integrates `python -m keel scan --staged`.
- **Exfiltration intent** (WebFetch to an attacker URL, rendering an image, DNS) is a permissions and
  isolation problem, not a pattern problem. Keel splits background runs so the web-facing one has no
  file tools, which removes the obvious channel but not prompt injection as a class.
