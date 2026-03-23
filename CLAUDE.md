<!-- codelicious:start -->

# codelicious

This project is managed by codelicious. Read `.codelicious/STATE.md` for
the current task list and progress.

## Rules
- Read existing files before modifying them.
- Run `/verify-all` after changes to catch issues early.
- Update `.codelicious/STATE.md` as you complete tasks.
- When done, write "DONE" to `.codelicious/BUILD_COMPLETE`.

## How to Work
- Use the **builder** agent for parallel code implementation.
- Use the **tester** agent to run tests and fix failures.
- Use the **reviewer** agent for security and quality checks.
- Use `/run-tests`, `/lint-fix`, `/verify-all` skills for common workflows.
- Use TodoWrite to track sub-steps within complex tasks.

## Git & PR Policy
- You own all git operations: add, commit, push, branch creation.
- Write clear, descriptive commit messages that explain what changed and why.
- One commit per logical unit of work (e.g. one task, one fix).
- Create PRs with meaningful titles and descriptions summarizing actual changes.
- NEVER push to main/master/develop/release branches directly.
- NEVER force-push or amend published commits.

<!-- codelicious:end -->
