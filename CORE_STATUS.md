# Arachne core status

This pre-release repository is the portable-core extraction from
`arachne-development`. It is the core review and build target for the intended
public project; it is not yet a published SDK or release.

## Boundary

The workspace contains exactly six portable Rust packages:

```text
arachne-security ──┐
arachne-store     ─┤
arachne-routing ──► arachne-delivery ──► arachne-runtime
                                      ▲
                                arachne-node
```

Android/JNI, Kotlin, ATAK, CoT translation, release packaging, device evidence,
relay services and experiments stay outside this repository. Application
payloads are opaque to the core.

## Current implementation

- Package and crate identifiers use the `arachne-*` / `arachne_*` namespace.
- `arachne-runtime::Client` is the typed native-consumer seam for lifecycle,
  workspace, membership, invitation, connectivity, interest and publication
  operations.
- The existing JSON/handle dispatcher remains internal compatibility plumbing;
  it is not the adopter-facing API.
- `arachne-store` exposes a caller-owned `FreshnessAnchor` so a valid older
  record image can be rejected after rollback.
- Membership convergence, invitation admission and route behavior have focused
  serialized Rust coverage without Android or ATAK execution.

## Verification

The following checks are the core gate:

```sh
cargo +1.98.0 check --locked --offline --workspace
cargo +1.98.0 test --locked --offline --workspace -- --test-threads=1
```

The typed consumer tests are in
`crates/arachne-runtime/tests/typed_client.rs`. Existing focused suites cover
atomic persistence, recovery, membership convergence, workspace naming,
invitation controls, event-driven admission and route capacity. Test execution
is serialized because the runtime has a process-wide session-capacity budget.

## Deliberate residual limits

1. The live recovery callback remains volatile. Durable application delivery
   acknowledgements and an application outbox are not implemented here.
2. The freshness anchor is caller-owned; the core does not provide a whole-DB
   rollback ledger or external monotonic counter.
3. Membership history, profile/name retention and conflict reconciliation are
   bounded; partition finality and unrestricted historical pagination are not
   selected contracts.
4. Invitation controls cover the current selected admission lifecycle, not a
   complete revocation/expiry policy product.
5. Route profiles and local WAN-shaped tests are available, but production
   relay availability, NAT traversal and stock-network qualification remain
   external evidence gates.

Do not add protocol versions, historical codecs, Android dependencies or relay
product code to close these limits without an explicit product decision.
