# Iroh 1.2.0 connection restart patch

**BLUF:** New QUIC handshakes try all known peer addresses. An old selected path must not hide a new address after the same endpoint identity restarts.

Source: crates.io `iroh` 1.2.0, upstream commit `17c0612f80f78f5288e97b818b1360ae6ea0a51a` (`iroh/`).
Archive SHA-256: `b2f8d1cfffc83efe39a1031aab423ce09cb8048071baba550508931e9a81ce46`.
License: MIT OR Apache-2.0, with the upstream BSD-3-Clause notices retained.

Only `src/socket/remote_map/remote_state.rs` changes upstream source. `State::handle_msg_send_datagram` uses the existing fanout over known addresses for QUIC Initial packets even when a path is selected. Established traffic keeps Iroh's normal path selection. Encryption, endpoint identity, ALPN negotiation, and access checks do not change.

The unpatched path sends new handshakes only to the selected path. A stopped process leaves that path selected until its old connections expire. An incoming connection from the restarted process can work while a new outgoing connection to its fresh address stalls.

Core's `crates/arachne-node/tests/moq_restart.rs` reproduces this with a real process kill, the same identity, a new port, and a protected payload round trip under three seconds. The patch passed three initial repeats in 0.294–0.307 seconds. This is a local transport check; tablet results are recorded separately.

Cargo ignores dependency-owned patches. Every application root must repeat `[patch.crates-io] iroh = { path = "<core>/vendor/iroh" }`. Keep one Iroh package identity across MoQ, Gossip, Blobs, and Core. Do not publish this source as an unmodified upstream crate.

Registry bookkeeping and the upstream Cargo.lock are omitted. The remaining archive source is retained for audit. MIT and Apache license texts are copied from the same upstream commit because the archive omits them.
