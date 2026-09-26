> Handoff brief H3. Updated 2026-09-26.

# H3: Test speed

## BLUF

H3 is complete. Commit `a6619db`, merged as `688946b`, optimizes dependencies
at level 2 in development and test builds. Arachne crates remain at level 0.
Debug assertions and overflow checks remain enabled.

## Evidence

The same-source comparison used Rust 1.98.0 and four build jobs. Each test ran
on CPUs 8–11, outside the shared build lock. All four tests passed in both runs.
The combined test time fell from 3654.565 seconds to 430.952 seconds. These are
single runs on a shared machine.

The [development guide](../../development.md#test-speed-and-build-cache-size) has the full before/after
table, build time, target size, profile settings and reproduction commands.
No optimization of Arachne workspace crates was needed. Later integration
suites retain four test threads; local Iroh fixtures must isolate their own
identities and multicast sockets.

## Scope

This package changes the test profile and documentation. It does not change
the production protocol, crypto settings, storage format or test assertions.
Later native storage and branch changes can change absolute test times. Do not
apply the old measurement to a different source revision as a benchmark.
