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
| 3 | `git am` / `git apply` | Closed | L1 blocks `am`; for `git apply … && git commit` L1 reads the patch itself (stdin or missing patch is blocked); L3 covers `am` | `test_history_written_without_commit_command`, `TestBypassResearch.test_git_apply_then_commit_reads_the_patch`, `test_git_apply_reverse_reads_removed_lines`, `test_ordinary_commits_with_apply_or_am_in_words` |
| 4 | `gh api` / `gh repo create --push` / gists / releases | Closed for content-writing endpoints | L1: `contents`, `git/*`, `releases`, `gists` with PUT/POST/PATCH **or with fields and no method** (gh defaults to POST), GraphQL `createCommitOnBranch`/`createRef`/`updateRef(s)`/`mergeBranch` or any GraphQL query read from a file; `gh.exe` and `bash -c` wrappers; `gh gist create`, `gh release create/upload` are escalated to the human | `test_history_written_without_commit_command`, `TestBypassResearch.test_gh_api_writes_without_explicit_method`, `test_gh_api_spellings`, `test_gh_publish_goes_to_human` |
| 5 | Scanner's own `git diff` runs `diff.external` / textconv | Closed | Scanner uses `--no-ext-diff --no-textconv --text`; L1 blocks setting them | `test_scanner_is_not_blinded_by_repo_config`, `test_scanner_tampering_blocked` |
| 6 | `GIT_EXTERNAL_DIFF`, `GIT_CONFIG_*` inherited by the scanner | Closed | Scanner scrubs the environment; L1 blocks setting them | same |
| 7 | `core.fsmonitor` command executed during the scan | Closed | Scanner forces `core.fsmonitor=false`; L1 blocks setting it | `test_scanner_tampering_blocked` |
| 8 | MCP terminals (`run_in_terminal`, `start_process`, `interact_with_process`, …) | Closed for conventional tool names | L1 matcher covers them; REPL input is read as code; L2–L3 cover everything else | `test_mcp_terminals_are_covered`, `test_mcp_terminal_uses_its_own_cwd`, `test_repl_input_is_read_as_code`, `test_matcher_selects_exactly_the_risky_mcp_tools` |
| 9 | MCP file writes bypassing `check_write` | Closed for conventional tool names | `write_file`, `edit_block`, `edit_file`, `write_pdf`, `create_file`, `update_file`, `append_file`, `move_file`; **every** text field is scanned, including nested lists and objects (`edits: [{newText}]`) | `test_mcp_write_tools_are_covered`, `TestBypassResearch.test_mcp_write_scans_every_field`, `test_mcp_nested_fields_are_scanned` |
| 10 | `MultiEdit` | Closed | L1 | `test_multiedit_is_scanned` |
| 11 | Secret split into concatenated literals | Closed for adjacent literals | Scanner joins `+`, `.`, `..`, `&` and implicit concatenation, across line breaks, in files and in diff blocks; the finding points at the key's line | `TestBypassResearch.test_split_secret_in_write`, `test_split_secret_in_commit` |
| 12 | Secret encoded (base64, hex) | Closed for aligned base64, base64url, hex, `\x..` | Scanner decodes candidate tokens and looks for the same key shapes. Misaligned encodings (a one-character prefix, odd-length hex), `\u` escapes and compression are **not** decoded | `TestBypassResearch.test_encoded_secret` |
| 13 | Secret in a binary, UTF-16 or unlisted file | Closed | Staged diff with `--text`; untracked files of any suffix; UTF-16 (BOM or NUL-interleaved) is decoded; long lines scanned in overlapping windows; files over 2 MB are scanned up to 2 MB and the truncation is reported | `test_scanner_sees_files_marked_binary`, `TestBypassResearch.test_binary_and_unlisted_files`, `test_utf16_secret_is_seen` |
| 14 | `secret-scan: ignore` pragma | Partly closed (by design) | The pragma never silences key shapes; a shell command that mentions the pragma and writes a file (including heredocs and `open().write`) is blocked; via Write/Edit/MCP, adding one, adding another or moving one into the first five lines is escalated to the human. A pragma assembled at runtime from fragments is a residual limit | `test_shape_token_survives_pragma_and_comment`, `test_second_wave_blocked`, `TestBypassResearch.test_new_pragma_goes_to_human`, `test_pragma_written_through_heredoc_or_code`, `test_pragma_moved_into_header_or_added_again` |
| 15 | Values tuned below the assignment heuristics (length < 12, entropy < 3.0, placeholder prefix) | Residual risk | Key shapes still match; generic assignments may slip | `test_real_non_secrets_are_not_flagged` documents the trade-off |
| 16 | `git` spelled through globs, substitution, escapes (`g?t`, `$'\x67it'`, `$(…)`, `g^it`) | Closed | L1 unglobs and expands; L2–L3 do not depend on spelling at all | `test_shell_expansion_of_git_name`, `test_indirect_commit_scans_worktree` |
| 17 | `core.hooksPath` that switches off L2–L3 | Closed for the agent | L1 blocks it in repo, worktree, global and XDG config, `-c`, `--config-env` and env vars; when a hook manager already set it inside the repository, `reference-transaction` is installed into that directory, excluded locally from git and protected from the agent by its marker; a hooks directory outside the repository is shared and left alone; `/keel:doctor` flags a repository whose hooks git will no longer run | `test_hook_tampering_blocked`, `TestBypassResearch.test_git_config_outside_repo_protected`, `test_growth.TestProject.test_husky_path_respected`, `test_doctor_sees_hooks_disabled_by_hooks_path`, `test_shared_hooks_path_outside_repo_is_left_alone`, `TestHooksPathReal`, `TestBypassResearch.test_keel_hook_in_hooks_path_is_protected`, `test_hooks_dir_cannot_be_removed_by_other_spellings` |
| 17b | Push to an arbitrary remote | Partly closed | Every push is scanned for secrets in unpushed commits; credentials in URLs are caught; pushing to a foreign remote as such is not blocked | `test_push_scans_unpushed_commits`, `test_push_scans_other_branches` |
| 18a | Input crafted to make the hook time out (Claude Code treats a hook timeout as *allow*) | Closed | Scanner passes are linear with no work cap (a cap was itself a bypass); risky requests (writes, anything mentioning git/gh or able to hide them) are checked in a child process with a 40 s deadline (the hook timeout is 60 s), because a regex holds the GIL and an in-process timer cannot interrupt it. A check that does not finish, or a crashed checker, **blocks** the write or commit | `TestBypassResearch.test_padding_cannot_buy_a_timeout`, `test_slow_check_becomes_a_block`, `test_hook_runs_through_watchdog`, `test_pathological_regex_input_stays_fast`, `test_split_secret_after_many_joins` |
| 18 | Claude Code deny-rule degradation after 50+ subcommands | Not applicable to L1 | The hook sees the whole command before execution | `TestBypassResearch.test_padding_does_not_hide_commit` |
| 19 | Claude Code command-parsing CVEs (`$IFS`, `find`, `sed`+`echo`, `cd`) | Out of scope | They bypass Claude Code's permission prompts, not Keel's hook; keep Claude Code updated | — |

## Known limits (what Keel does not claim)

- **"Is this a commit?" is undecidable from command text.** L1 is an early, best-effort gate. L2–L3
  are git-native and spelling-independent; L4 is the only authoritative boundary.
- **Runtime assembly.** A secret built from separate variables or `"".join([...])`, or read from a file
  at run time, is not reassembled by the scanner. Misaligned or other encodings (a prefix before
  base64, odd-length hex, `\u` escapes, compression, ROT13, double encoding) are not decoded. L4 is the answer.
- **Scan budget.** Each file is scanned up to 2 MB (the truncation is reported). Measured on this
  machine: 1.9 MB of random binary 0.4 s, 1.5 MB of JSON 1.0 s, 40 000 base64 lines 1.6 s.
- **Unconventionally named MCP tools** and agents outside this Claude Code session are invisible to L1;
  only L2–L4 apply.
- **Destructive code instead of commands.** `python -c "shutil.rmtree('.husky')"` removes the hooks directory
  without a recognisable command; `/keel:doctor` then reports the repository as unprotected.
- **Latency.** Risky requests pay one extra Python start for the watchdog (about 0.7 s measured on the
  author's Windows laptop); ordinary reads and commands do not.
- **A human can override** L2–L3 in their own terminal (`KEEL_ALLOW_SECRET=1 git commit --no-verify`);
  the override is loud. The agent cannot set the variable or the flag.
- **A pre-existing foreign hook** of the same name is never overwritten; `init-project` reports it and
  the human integrates `python -m keel scan --staged`.
- **Exfiltration intent** (WebFetch to an attacker URL, rendering an image, DNS) is a permissions and
  isolation problem, not a pattern problem. Keel splits background runs so the web-facing one has no
  file tools, which removes the obvious channel but not prompt injection as a class.
