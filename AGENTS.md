<!-- agent-sync:start (managed by agent-sync - edit outside these markers) -->
## Multi-machine sync protocol (Windows + Kali)
This repo is worked on from more than one machine. **GitHub is the source of truth.**

**Before any work**
1. Run `agent-sync pull` (or `git pull --rebase`). Never start on a stale tree.
2. If `git status` shows changes you didn't make, stop and ask before touching them.
3. Read `docs/HANDOFF.md` first - it has the current task, decisions and next steps. Don't re-explore the repo if it already answers your question.

**While working (keep token use low)**
- Skip `node_modules`, `dist`, `build`, `.venv`, lockfiles and generated files unless the task needs them.
- Catch up with `git log --oneline -10` and `git diff --stat`, not full-file reads.
- Search (`rg`/`grep`) before opening files; open only the parts you need.

**When a task or loop is finished**
1. Update `docs/HANDOFF.md` (40 lines max): what changed, current state, next steps, open questions.
2. Run quick tests/lint if they exist.
3. Commit with a clear message, then run `agent-sync push` (or `git pull --rebase && git push`).
4. Never commit secrets (`.env`, keys, tokens) and never force-push. If the push fails or the rebase conflicts, stop and report.
<!-- agent-sync:end -->
