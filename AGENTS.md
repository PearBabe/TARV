# Agent Operating Guide

This repository uses lightweight handoff files so Codex can recover cleanly after
context compaction, model changes, or thread changes.

## Start Of Work

- Before starting a non-trivial task, read `.codex/PROJECT_STATE.md` and
  `.codex/SESSION_LOG.md` if they exist.
- Treat `.codex/PROJECT_STATE.md` as the current handoff source of truth.
- Do not restart broad exploration when the state file points to specific files
  or commands. Inspect the referenced files first.
- Use `rg` or `rg --files` for search whenever possible.
- Protect user work. Never revert existing changes unless the user explicitly
  asks for that operation.

## Long Task Continuity

- Keep the main conversation focused on goals, decisions, risks, and next
  actions. Avoid pasting long logs into chat or state files.
- After each milestone, update `.codex/PROJECT_STATE.md` with the current status,
  changed files, verification results, blockers, and at most three next steps.
- Append a short entry to `.codex/SESSION_LOG.md` when meaningful progress is
  made. Include the command/result summary, not full output.
- If `.codex/PROJECT_STATE.md` grows beyond roughly 250 lines, move stale details
  to `.codex/archive/` and keep only the active handoff.

## Subagent Use

- Use subagents only when the user explicitly asks for subagents, delegation, or
  parallel agent work, or when the current tool policy explicitly permits it for
  the task.
- Prefer subagents for read-heavy exploration, test failure analysis, log
  triage, and independent implementation slices.
- Do not assign overlapping write scopes to multiple workers.
- Every subagent result should include: conclusion, evidence files, changed
  files if any, verification commands, and unresolved questions.
- Close completed subagents when their result is integrated.

## Build And Verification

- For MoniTAal, prefer:
  `cmake -S MoniTAal -B MoniTAal/build -DMONITAAL_BUILD_BIN=ON -DMONITAAL_BUILD_TEST=ON -DCMAKE_INSTALL_PREFIX="$HOME/.local"`
  then `cmake --build MoniTAal/build -j"$(nproc)"` and
  `ctest --test-dir MoniTAal/build --output-on-failure`.
- For MightyPPL, inspect its README and current local changes before rebuilding.
  Its build may depend on ANTLR and Java paths.
- Report any skipped verification explicitly.
