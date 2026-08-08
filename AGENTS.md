# AGENTS.md — Mandatory AI Repository Rules

> **ChatGPT / Codex / other coding agents: read this file before any repository action.**
> These are standing user instructions. Do not wait for the user to repeat them in a new chat.

## Canonical branch
- Canonical development branch: `main`.
- New code work starts from the latest `main`.
- Read-only diagnosis does not require a branch.

## One task = one temporary branch
- Before creating a branch, check for an existing active branch/PR for the same task.
- Otherwise create exactly one short-lived task branch from the latest canonical branch.
- Keep revisions on that same branch. Do not create auxiliary `v2`, `v3`, `final`, `current`, `backup`, `test`, `build`, `deploy`, `handoff`, `note`, or packaging branches.
- Do not use branches as chat memory, backups, artifacts, or task-status records.
- Track unfinished work in GitHub Issues or repository task-state documentation.

## Builds, releases, and history
- Use CI/Actions artifacts for build and deployment packages.
- Use tags for immutable candidates, releases, production snapshots, or archived historical states.
- Preserve unique old history with a verified `archive/*` tag before branch deletion.
- Never delete unique history just because a branch looks old.

## Task completion
A task is complete only after implementation, tests/CI, PR merge, canonical-branch verification, temporary-branch deletion, and Issue/task-state update.

## Git safety
Unless the user explicitly authorizes a narrowly scoped recovery operation, do not use force push, `git reset --hard`, history-rewriting rebase, `git clean`, `git stash`, destructive ref moves, or automatic branch switching as an error-recovery shortcut.

If the worktree is dirty, origin/branch is unexpected, history diverges, or the safe path is unclear: stop and report exact state instead of rewriting history.

Never commit secrets, tokens, credentials, local environment files, sensitive diagnostics, or unrelated generated files.

## AI takeover protocol
At the start of every task:
1. read this file and any more specific nested `AGENTS.md`;
2. identify current branch, canonical branch, origin, and working-tree status;
3. inspect the relevant Issue/PR if referenced;
4. discover and respect repository-specific build/deploy docs before changing runtime or production state;
5. make the smallest safe change on one task branch.

Destructive Git operations, branch/tag deletion, production deployment, or service restart require explicit user intent and fresh safety checks immediately before execution.

## Long-term branch budget
Persistent branches should stay minimal. Temporary feature/fix branches exist only while their task is active and are deleted after merge.
