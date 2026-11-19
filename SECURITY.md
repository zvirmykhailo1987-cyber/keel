# Security policy

Keel is a safety net for AI agents in a repository, so a bypass of its gate is a security issue.

## Reporting

Please report a vulnerability privately through GitHub: **Security → Report a vulnerability** on this
repository. Include the exact tool call or command, the expected and the observed result (exit code or
"ask"), your OS, Python, git and Claude Code versions. Do not include real secrets: synthetic values with
the same shape are enough.

## Scope

- Ways to commit, push, write or publish a secret, or to move a branch past the checks, that
  `docs/THREAT-MODEL.md` lists as closed.
- Ways to make the gate fail open (crash, timeout, encoding) for a write or a commit.
- Anything that lets the agent remove or disable Keel's git hooks or its state.

Items listed under *Known limits* in the README and the threat model are known and documented; a
practical way to close one is still very welcome.

## Supported versions

Only the latest release on `main` is supported while the project is in beta.
