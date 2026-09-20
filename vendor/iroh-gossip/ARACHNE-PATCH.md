# Arachne shared dial admission

Upstream: `iroh-gossip` 0.101.0, crates.io archive SHA-256
`4e1dc4b05f73e7a1b9e83b531eb63c3fd671b0af3aeb13b59c546dd7ca747515`.
MIT/Apache-2.0 licenses and published source files are retained. Repository
administration files and the package-local lockfile are not needed by this root
workspace build. `Cargo.toml` is the published normalized manifest.

Only `src/net.rs` is changed: `Builder::dial_capacity(Arc<Semaphore>)` passes a
host-owned semaphore to the existing native dial task. Waiting for a permit and
the complete Iroh dial live inside the existing cancellation scope. Success,
failure, cancellation and actor shutdown drop the permit. The actor still owns
its peer-deduplicated queue, retries, routing and gossip state machine. No wire
format, protocol version, crypto or dependency version changes.

Arachne supplies one gossip-dial semaphore, separate from the data and control
dial slots, to every workspace gossip instance. Data dials to offline peers
therefore cannot delay a gossip link to a live member (ADR 0009).
An endpoint hook separately bounds established connections, including gossip,
without retaining strong connection handles.

Remove this patch when upstream provides equivalent cancellation-safe shared
dial admission. A before-connect hook alone cannot release capacity after failed
or cancelled attempts; a post-handshake hook cannot bound pending dials.

The root source-archive check includes this path. Focused checks in
`crates/arachne-node/src/budget.rs` exercise native gossip dialing, queued/active
cancellation, shared capacity, control reserve and weak connection accounting.
