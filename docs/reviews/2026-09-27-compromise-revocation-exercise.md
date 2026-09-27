# Compromise and revocation exercise

Date: 2026-09-27

Scope: Core `integrate/wave1` at `005bc6f`. This is a local deterministic
exercise; it does not claim a live device, relay, Tor, signing-store, or public
advisory drill.

## Exercise 1: member private-state compromise

Assumption: an attacker copied a current member's MLS private state, and the
operator has regained control of the device.

Action: perform a self-update and require every member to adopt the authenticated
commit. The security test proves that the member's leaf key changes and peers
converge on the new epoch. Availability requires the uncompromised process to
complete and distribute the update. If attacker control may continue, remove and
re-invite the member instead.

```text
flock /home/user/development/worktrees/.cargo-build.lock nice -n 10 \
  env CARGO_BUILD_JOBS=4 cargo test --locked -p arachne-security \
  a_member_self_update_is_accepted_and_rotates_its_keys
```

Result: 1 passed, 0 failed, 0 ignored (98 filtered out).

## Exercise 2: endpoint/member revocation

Assumption: an endpoint key or member device is lost. The administrator removes
the member, the removed device restores its saved state, and an active fallback
must not reopen the workspace.

Action: make the removal durable before rotating/re-inviting. The runtime
`removed_membership` integration test proves restored removed state shuts down
and rejects active fallback. This prevents a removed device from silently
resuming from older active state; network delivery to offline members remains an
availability limit and does not replace durable removal.

```text
flock /home/user/development/worktrees/.cargo-build.lock nice -n 10 \
  env CARGO_BUILD_JOBS=4 cargo test --locked -p arachne-runtime \
  --features test-fixtures --test removed_membership
```

Result: 1 passed, 0 failed, 0 ignored. The test needs permission to bind local
sockets; a sandboxed attempt failed at that boundary before the escalated run
passed.

## Outcome

The code paths for post-compromise self-update and durable member revocation are
testable and fail closed on removed-state restore. The operational runbook must
still be exercised with real release-signing credentials and live Android
devices before a production release. That remaining work is a release gate, not
evidence supplied by this local exercise.
