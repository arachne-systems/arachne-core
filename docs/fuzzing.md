# Fuzzing

The `fuzz/` workspace uses `cargo-fuzz` and libFuzzer against four untrusted
input boundaries:

| Target | Boundary | Maximum input |
| --- | --- | --- |
| `security_decoders` | Invitations, MLS membership-step wrappers, fork keys, revocation orders, branch records | 2 MiB |
| `delivery_wire` | Direct, range, cutoff, current-value, and current-view wire records | 128 KiB |
| `persistence_decoders` | Delivery snapshots and freshness anchors restored from authenticated storage | 512 KiB |
| `runtime_requests` | Legacy JSON request and stored-join parsing beneath the typed client | 128 KiB |

Successful parses are encoded and parsed again where the type has a canonical
encoder. A mismatch is an invariant failure. Rejections are expected; panics,
timeouts, excessive allocation, and sanitizer findings are failures.

The corpus contains synthetic, non-secret fixtures built from the production
format prefixes and bounds. Add every minimized crash or hang that is fixed as
a permanent corpus regression.

## Local commands

Install `cargo-fuzz` 0.12.0 and use the pinned nightly from CI. Run one bounded
campaign:

```bash
cargo +nightly-2026-07-29 fuzz run security_decoders \
  fuzz/corpus/security_decoders -- \
  -max_total_time=300 -max_len=2097152 -timeout=10
```

Replace the target and maximum length with the table value. On the shared
Arachne machine, wrap every Cargo command with the build lock required by
`AGENTS.md`.

Minimize and preserve a failure:

```bash
cargo +nightly-2026-07-29 fuzz tmin security_decoders \
  fuzz/artifacts/security_decoders/crash-...
```

Copy the minimized artifact reported by `cargo-fuzz` into the target's corpus.
Then add a focused deterministic unit or integration test when the failure can
be expressed without libFuzzer, so the same decoder is continuously exercised.

CI runs 1,000 iterations or 30 seconds per target, whichever arrives first.
That smoke job catches known-corpus regressions and basic sanitizer failures;
it is not a substitute for longer local or scheduled campaigns.
