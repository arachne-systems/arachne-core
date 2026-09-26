# Foreground deadline isolation — 26 September 2026

## BLUF

A per-operation deadline cancelled unrelated background control requests.
The new code limits only the foreground wait. The two isolation tests and
all 15 lifecycle tests pass. No device result is claimed for this change.

## Cause and change

The mobile source base is `b05dd80f66957c417f56a8fdd1567cfa4fdd0e04`.
`Entry::arm_deadline` sent the node-wide cancellation watch signal when a
foreground deadline elapsed. Background presence, recovery, and membership
requests use the same signal. Thus a 20 ms publication deadline could stop
those requests, even when the publication used a separate transport path.

Remove the detached deadline task and its generation counter. Pass the
operation deadline directly to each foreground control wait. This includes
raw control, nearby invitation and discovery, invitation checkpoint fetch,
admission and its history pages, and leave through a peer. Existing policy
and publication waits already use the operation deadline.

Background workers keep their own limits. They receive no ambient operation
token. Explicit node cancel and close retain the shared cancellation signal.
An operation whose deadline elapsed while it waited for the session lock
does not enter its body.

No public API, wire format, storage format, transport dependency, or MoQ
worker changes are included.

## RED evidence

`registry::tests::an_operation_deadline_preserves_an_earlier_background_control_exchange`
failed on the unchanged production base. A real local peer held the background
request. A separate foreground request reached its 20 ms deadline. The
background task ended with `Err(Cancelled)` before the peer could reply.

- Build: `/tmp/moq-deadline-red-build.jsonl` and `.log`.
- Failure: `/tmp/moq-deadline-red-test.log`.
- Result: 0 passed, 1 failed, exit 101.

## GREEN evidence

Build with Rust 1.98.0, locked dependencies, `moq`, no incremental cache,
and no debug symbols. Run test binaries outside the shared build lock on
CPUs 4–7 with four test threads.

| Gate | Result | Receipt |
| --- | --- | --- |
| Runtime registry tests | 4 passed | `/tmp/moq-deadline-final-registry.log` |
| Deadline helper tests | 3 passed | `/tmp/moq-deadline-final-helper.log` |
| Runtime lifecycle tests | 15 passed | `/tmp/moq-deadline-final-lifecycle.log` |
| Focused compile | Passed | `/tmp/moq-deadline-final-build.jsonl` and `.log` |
| Patch whitespace | Passed | `git diff --check` |

The isolation cases cover a background request started before the operation
and a request started during it through an independent control client. Each
request stays pending after the foreground timeout, then returns the exact
reply bytes. The same test also waits beyond the completed foreground
operation, so a late timer cannot cancel the request.

The lifecycle suite covers repeated foreground deadlines, explicit cancel,
close during a blocked operation, session reuse, and endpoint bind limits.
The helper and registry tests reject expired work before its body runs.

An independent read-only review by the SDK agent found no blocking standards
or specification issue. It checked every blocking control caller, background
worker scope, explicit cancel and close, and the final test receipts.

## Limits and next gate

The session uses a blocking standard mutex. Waiting for another operation's
lock can exceed the configured deadline. This is unchanged. The new guard
prevents late work after that wait; it does not claim to bound the lock wait.

The earlier intermittent tablet result (16 of 20 complete talks) has no
proven single cause. This receipt proves a control cancellation defect. It
does not prove that this defect caused each missing audio boundary.

The lead agent must forward-merge this change into the integrated source,
repeat its full qualification suite, and pin the mobile build for device
checks. Preserve the original RED receipt.
