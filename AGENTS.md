# Agent instructions

## Trunk flow (every agent: Claude, Codex, subagents)

- The trunk of this repository is `integrate/wave1`. All finished work flows into it.
- Start each task on a new branch from the trunk. One task per branch.
- When the work is finished and its tests pass, stop. Report the branch name to the owner. The integrator (one Claude session) lands it into the trunk; do not merge into the trunk yourself.
- Do not make new long-lived branches or integration lines.
- Do not push, and do not move submodule or SDK pins, unless the owner says so.
- `main` is the published line. Its history differs from the trunk (the trunk also has the history from before the 2026-09-21 squash). Only the owner decides when and how the trunk becomes `main`.
