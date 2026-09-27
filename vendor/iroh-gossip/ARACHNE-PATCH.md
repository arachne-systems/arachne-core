# Arachne shared dial admission

Upstream: `iroh-gossip` 0.101.0, crates.io archive SHA-256
`4e1dc4b05f73e7a1b9e83b531eb63c3fd671b0af3aeb13b59c546dd7ca747515`.
MIT/Apache-2.0 licenses and published source files are retained.

Published as the renamed fork `arachne-iroh-gossip`, version
`0.101.0-arachne.1`. The Rust library name stays `iroh_gossip`. The earlier
`arachne-iroh-gossip` 0.101.0 release reused the upstream number; under semver
it sorts above `0.101.0-arachne.1`, so dependents must pin the fork with `=`.

## Complete list of differences from the published upstream archive

Found with `diff -ru` against the crates.io archive
(`~/.cargo/registry/src/*/iroh-gossip-0.101.0`).

### `src/net.rs`

1. **Shared dial capacity.** `Builder::dial_capacity(Arc<Semaphore>)` stores a
   host-owned `tokio::sync::Semaphore` (new `Builder.dial_capacity` field,
   default `None`). `Builder::spawn` passes it to `Actor::new`, which passes it
   to `Dialer::new` (new `Dialer.capacity` field). In `Dialer::queue_dial`, the
   spawned dial task first waits for an owned permit and then runs
   `endpoint.connect`. Both steps are inside the existing `tokio::select!`
   with the cancellation token, so a cancelled dial stops waiting or connecting.
   The permit drops when the dial task ends (success, failure, cancellation or
   actor shutdown). If the semaphore is closed, the dial ends as `None`
   ("dial disconnected"). With no semaphore, behavior is the upstream behavior.
2. **`dialing` flag in the pending-peer state machine.** `PeerState::Pending`
   gets a new field `dialing: bool` (default `false`).
   - Upstream starts a dial when a message is queued for a pending peer whose
     queue is empty. Arachne starts a dial when no dial is in flight
     (`!dialing`), and then sets `dialing = true`.
   - When the dialer reports a failed dial (`Some(Err(_))`) or a disconnected
     dial (`None`) for a peer that is still `Pending`, the actor sets
     `dialing = false`. Thus the next queued message starts a new dial.
   - Reason: upstream uses "queue is empty" as a proxy for "no dial in
     flight". That proxy fails when a dial ends but the peer stays `Pending`
     with queued messages. For example, the `None` path (cancelled dial, or a
     closed semaphore) does not remove the peer. Upstream would then never
     start a new dial for that peer, because the queue is not empty. The flag
     makes "at most one dial in flight per pending peer" explicit and lets the
     next queued message dial again.
   - `PeerState::accept` ignores the new field (`Pending { queue, .. }`).
3. **Call-site update.** `Actor::new` takes a new last argument
   `dial_capacity: Option<Arc<Semaphore>>`. The in-crate test helper that
   calls `Actor::new` passes `None`.
4. `Semaphore` is added to the `tokio::sync` import.
5. **Dial deadline.** `Builder::dial_timeout(Duration)` bounds each dial
   attempt inside the same task, so a silent peer returns the shared dial
   permit at the host's deadline instead of when Iroh gives up. A timeout is
   reported as a failed dial.
6. **Connection preamble (the one wire addition).**
   `Builder::connect_preamble(Bytes)`: every connection the instance dials
   first carries these bytes on its own unidirectional stream, before any
   gossip stream. Arachne uses one fixed gossip ALPN for all workspaces and
   sends a keyed workspace tag this way, inside the encrypted connection, so
   the TLS ClientHello does not name the workspace. The accepting side reads
   the preamble before it calls `Gossip::handle_connection`; gossip itself
   never sees it.
7. **Connection churn cleanup.** Adapt the fixes and regression checks from
   upstream pull request #154 (commit `90a1af0`): stop a send loop when its
   channel closes, close that superseded connection so its paired receive loop
   also ends, and remove closed or failed peers from the actor map. Simultaneous
   dials choose the same physical connection at both endpoints before closing
   the redundant link. Failed dial cleanup is limited to inactive peers so a
   concurrently accepted connection remains live.

No protocol version, crypto or dependency version changes. Item 6 adds bytes
before the gossip streams on dialed connections.
The actor still owns its peer-deduplicated queue, retries, routing and gossip
state machine.

### Other files

- `src/net/util.rs`, `src/proto/state.rs`, `src/proto/hyparview.rs`, and
  `src/proto/plumtree.rs`: port upstream pull request #154's cleanup of stale
  per-peer state after disconnect, timeout, or eviction. These changes do not
  alter the wire protocol.

- `src/bin/sim.rs`: remove a redundant borrow in a formatting argument for
  Rust 1.98 Clippy. This diagnostic binary keeps the same behavior.

- `Cargo.toml` (normalized manifest): `name = "arachne-iroh-gossip"`, version
  `0.101.0-arachne.1`, "Arachne Systems" added to `authors`, new
  `description` and `keywords`, `license` normalized from `MIT/Apache-2.0` to
  the SPDX expression `MIT OR Apache-2.0` (same terms), and new `repository`,
  `homepage`, `documentation`, `publish = ["crates-io"]` and
  `exclude = ["Cargo.toml.orig"]` fields. Dependencies are unchanged.
  `Cargo.toml.orig` is the unchanged upstream original.
- `README.md`: a fork banner at the top.
- `ARACHNE-PATCH.md` (this file) is added.
- Removed (repository administration, not needed by this workspace build):
  `.cargo/`, `.config/`, `.github/`, `.gitignore`, `CHANGELOG.md`,
  `Makefile.toml`, `cliff.toml`, `code_of_conduct.md`, `deny.toml`,
  `release.toml` and the package-local `Cargo.lock`.

## Why

Arachne supplies one gossip-dial semaphore, separate from the data and control
dial slots, to every workspace gossip instance. Data dials to offline peers
therefore cannot delay a gossip link to a live member. An endpoint hook
separately bounds established connections, including gossip, without keeping
strong connection handles.

Remove each part of this patch when upstream provides its equivalent. A
before-connect hook alone cannot release capacity after failed or cancelled
attempts; a post-handshake hook cannot bound pending dials. Remove the churn
cleanup when upstream pull request #154 lands in the pinned release.

The root source-archive check includes this path. Focused checks in
`crates/arachne-node/src/budget.rs` exercise native gossip dialing, queued/active
cancellation, shared capacity, control reserve and weak connection accounting.
