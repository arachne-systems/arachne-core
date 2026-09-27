# ADR: separate Tor onion and Iroh endpoint keys

Status: proposed for independent cryptographic review. Do not implement or
claim the finding closed until the review questions below are answered.

## Problem

The current Tor adapter expands the Iroh endpoint Ed25519 seed and passes the
expanded signing key to the Tor control daemon in `ADD_ONION`. A compromised
daemon can therefore sign as the Iroh endpoint, including MLS endpoint-binding
messages and gossip envelopes. The deterministic onion address also lets any
caller derive a route from an endpoint ID, but that convenience creates the
key-reuse failure.

## Decision

Use an independently generated 32-byte Ed25519 seed for the onion service.
Store it with the endpoint credential under the same device protection, but
never derive either key from the other and never give the endpoint seed to the
Tor control process.

Publish a canonical, endpoint-signed route record:

```text
version:       u8 = 1
endpoint_id:   [u8; 32]
onion_key:     [u8; 32]
generation:    u64
signature:     Ed25519(endpoint key,
               "arachne/tor-route/1\0" || preceding fields)
```

`onion_key` is the Tor v3 service public key. `generation` starts at one and
increases on every onion-key rotation. Receivers reject an invalid signature,
an endpoint mismatch, an unsupported version, a generation below the highest
durably accepted generation, or conflicting bytes at the same generation.

The current route record is also a required MLS leaf extension. The existing
endpoint-binding signature covers its hash with the workspace ID, member ID,
and MLS signature key. An MLS self-update changes the route record. This makes
the accepted group state, rather than an unauthenticated discovery response,
the authority for routes to current members.

An invitation carries the inviter's route record inside its existing signed
and checkpoint-bound data. A pending join uses only that record to reach the
inviter. After admission, members learn current records from the verified MLS
ratchet tree. Address lookup may cache records, but it cannot override the
record in accepted MLS state.

## Rotation and migration

1. Generate and durably save the new onion seed and next generation before
   announcing it.
2. Register the new onion service while the old service remains available.
3. Prepare, save, read back, and adopt an MLS self-update containing the new
   route record.
4. Announce the saved membership step through existing paths.
5. Retain the old service for the bounded membership recovery window, then
   remove it. The old endpoint-ID-derived service is disabled after migration.

An existing installation first generates an independent onion seed at
generation one. It keeps the legacy onion service only during the same overlap
window. A member that missed the update may need a fresh invitation or another
already authenticated member to recover the new route; the old deterministic
mapping is never accepted as a fallback after migration is recorded.

The onion seed, generation, and highest accepted peer generations are native
security records. Rollback protection follows the endpoint credential and MLS
state. A host that cannot persist them must fail Tor startup rather than make a
new service silently.

## Security properties and limits

- Compromise of the Tor daemon exposes the onion service key and permits route
  takeover or denial of service. It does not expose the Iroh endpoint signing
  key. Iroh TLS still authenticates the expected endpoint after routing.
- A substituted route without the endpoint signature is rejected before dial.
  A record signed by a removed member is not current workspace authority.
- Replaying an older generation is rejected after a newer generation has been
  saved. A fresh device that has no current MLS state can still be routed to an
  old, correctly signed invitation record; the invitation expiry and
  checkpoint rules remain the freshness boundary.
- Endpoint IDs, onion addresses, generations, timing, and traffic sizes remain
  metadata visible to members or observers at their respective boundaries.
- Onion rotation is an MLS membership change and can partition a node that
  removes the old route before peers receive the saved update.

## Required implementation and tests

1. `arachne-iroh-tor-transport`: accept an independent onion seed and an
   authenticated address-book entry instead of deriving an onion address from
   `EndpointId`; reject unknown mappings.
2. `arachne-security`: version the required leaf extension, bind the route
   record, validate generation changes on self-update, and expose current
   records from verified state.
3. runtime/store: save the local seed/generation and accepted peer generations
   in the same candidate transaction; restore before Tor bind.
4. SDK/mobile: wrap the onion seed with Android Keystore and exclude it from
   backup just like the endpoint credential.
5. compatibility: migrate through dual service overlap; do not retain the
   endpoint-derived address as a silent fallback.

Tests must reject endpoint substitution, onion-key substitution, signature
changes, generation rollback, conflicting same-generation records, unsaved
local rotation, stale invitation routes, and a route that differs from the
accepted MLS leaf. A two-node Tor test must rotate one service, reconnect after
both nodes restart, and prove the old service can be removed without exposing
the endpoint key to the Tor control client.

## Independent review questions

1. Is an endpoint-signed route record plus MLS leaf binding sufficient to keep
   discovery from becoming an identity authority?
2. Is `generation` with durable highest-seen state adequate for replay, given
   invitation and device rollback behavior?
3. Should rotation be an MLS self-update, or does it require an administrator
   authorized management transition?
4. Is dual registration during the recovery window safe for the intended Tor
   metadata and unlinkability claims?
5. Which exact native records must share one rollback/freshness transaction?

Record the reviewer, reviewed commit, answers, and resulting changes in
`ptt-60z.3.2` before implementation is marked ready for production.
