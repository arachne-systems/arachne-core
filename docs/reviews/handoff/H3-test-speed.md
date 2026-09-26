> Written by Claude (AI). Handoff brief H3.

# H3: Test speed

## BLUF

Runtime tests now run in parallel (default thread count). But three tests take 12–26 minutes in
debug builds, most likely because the crypto dependencies are not optimized. A profile experiment
was started and not measured.

## Start here

- Branch `feat/a4-context`, worktree `~/development/worktrees/arachne-core-a4-context`.
- WIP commit `f84acfe`: 17 lines in the root `Cargo.toml` (dependency opt-level profile). Not measured.

## Slow tests (debug build)

| Test | Time |
| --- | --- |
| lib `membership::gossiped_names_from_a_join_wave_survive_until_their_steps_land` | ~12 min |
| `tests/record_storage.rs` (2 tests) | 740 s |
| `native_persistence` `hundred_member_runtime_commits_tokens_and_reopens_without_legacy_snapshots` | ~26 min |

## Work

- [ ] Measure the three tests before the change (same CPUs, pinned).
- [ ] Try `[profile.dev.package."*"] opt-level = 2` (dependencies only; our crates stay debug). Measure again. Report build time and disk use too.
- [ ] If not enough, try opt-level 1 for the crypto-heavy workspace crates.
- [ ] Check whether `arachne-node`, `arachne-security`, `arachne-delivery` and `arachne-store` still need `--test-threads=1`. Remove any leftover need.
- [ ] Update `README.md` and `docs/development.md` test commands.

## Done when

- A clear before/after table. Commit the profile only if the gain is clear.
- The documented test commands match what works.
