# Vendored dependency exit review

Evidence captured 2026-09-26. This review covers every directory under
`vendor/` in Arachne Core.

## Decision

No complete fork can be removed immediately. All six forks are based on the
newest crates.io release, so a version bump alone does not remove any fork.
The closest exit is mDNS after upstream PR #15 merges and ships. Iroh has
absorbed the bounded send machinery after 1.2.0, but its current implementation
still lacks Arachne's restart behavior.

| Arachne fork | Owner area | Published upstream | Exit state |
| --- | --- | --- | --- |
| `vendor/iroh` | Core transport | [`iroh` 1.2.0](https://crates.io/crates/iroh/1.2.0) | Partially upstream on `main`; residual restart fix remains |
| `arachne-iroh-gossip` 0.101.0-arachne.1 | Gossip overlay | [`iroh-gossip` 0.101.0](https://crates.io/crates/iroh-gossip/0.101.0) | Churn replacements open; host hooks absent |
| `arachne-iroh-mdns-address-lookup` 0.5.0-arachne.1 | LAN discovery | [`iroh-mdns-address-lookup` 0.5.0](https://crates.io/crates/iroh-mdns-address-lookup/0.5.0) | Direct upstream fix open |
| `arachne-iroh-blobs` 0.103.0-arachne.1 | Resource transfer | [`iroh-blobs` 0.103.0](https://crates.io/crates/iroh-blobs/0.103.0) | APIs and bounds absent; GC defects open |
| `arachne-bao-tree` 0.16.1-arachne.1 | Resource verification | [`bao-tree` 0.16.1](https://crates.io/crates/bao-tree/0.16.1) | One dependency feature change absent |
| `arachne-iroh-tor-transport` 0.1.0-arachne.1 | Tor transport | [`iroh-tor-transport` 0.1.0](https://crates.io/crates/iroh-tor-transport/0.1.0) | Security replacement absent |

## Exit ledger

### 1. Iroh

**Why the patch exists.** A stopped peer can leave a selected path behind. A
new QUIC Initial then follows that stale path instead of a newly learned
address. Arachne fans Initials across known addresses and moves sends into 16
bounded tasks with a three-second deadline. See the local
[`ARACHNE-PATCH.md`](../../vendor/iroh/ARACHNE-PATCH.md).

**Upstream status.** Upstream merged the task limit and deadline in
[#4512](https://github.com/n0-computer/iroh/pull/4512), followed by cleanup in
[#4525](https://github.com/n0-computer/iroh/pull/4525), after the 1.2.0
release. Current `main` therefore contains equivalent actor responsiveness,
but it still chooses only the selected path whenever one exists
([source](https://github.com/n0-computer/iroh/blob/4d93a442f68f0cc090d494f072ad82c2b064188b/iroh/src/socket/remote_map/remote_state.rs#L793-L866)).
That does not cover Arachne's same-identity, new-address restart case. No
upstream issue or PR for that residual behavior was found.

**Exit condition.** Use a released Iroh version that includes #4512/#4525 and
also retries a newly learned address despite a stale selected path. Remove the
fork only after `moq_restart` and the runtime and SDK handshake regressions pass
against unpatched upstream. A next Iroh release can shrink this patch, but does
not yet eliminate it.

### 2. Iroh Gossip

**Why the patch exists.** Arachne adds a host-owned dial semaphore, a dial
deadline, explicit pending-peer dial state, and an encrypted connection
preamble used for the workspace tag. It also carries connection and peer-state
cleanup for churn. See the local
[`ARACHNE-PATCH.md`](../../vendor/iroh-gossip/ARACHNE-PATCH.md).

**Upstream status.** Released 0.101.0 and current `main` expose none of
`dial_capacity`, `dial_timeout`, or `connect_preamble`; current dialing only
deduplicates by endpoint and waits on `Endpoint::connect`
([source](https://github.com/n0-computer/iroh-gossip/blob/f128b98705f5ad3a28a92f1d2b483686348b6ae8/src/net.rs#L993-L1031)).
Current connection cleanup still waits for both halves, and the send loop still
does not explicitly handle a closed channel
([connection loop](https://github.com/n0-computer/iroh-gossip/blob/f128b98705f5ad3a28a92f1d2b483686348b6ae8/src/net.rs#L880-L900),
[send loop](https://github.com/n0-computer/iroh-gossip/blob/f128b98705f5ad3a28a92f1d2b483686348b6ae8/src/net/util.rs#L225-L238)).
Earlier churn submissions #146, #147, and #154 were closed unmerged in favor
of the upstream maintainer's open replacements
[#161](https://github.com/n0-computer/iroh-gossip/pull/161) and
[#162](https://github.com/n0-computer/iroh-gossip/pull/162). The separate
dialer work in [#120](https://github.com/n0-computer/iroh-gossip/pull/120)
does not supply Arachne's shared admission or preamble hooks.

**Exit condition.** Wait for released equivalents of all five host needs:
shared dial admission, a per-attempt deadline, retryable pending-peer state, an
encrypted preamble hook, and complete churn cleanup. Then run Arachne's dial
budget, preamble, retry, churn, and critical-delivery regressions against the
unforked crate. The churn portion may retire first after #161 and #162 ship;
the complete fork cannot.

### 3. Iroh mDNS address lookup

**Why the patch exists.** Upstream detects a changed peer advertisement but
keeps the first cached value with `or_insert`. After an app restart, a later
lookup can therefore return the old UDP port. Arachne replaces the cached value
and isolates multicast tests. See the local
[`ARACHNE-PATCH.md`](../../vendor/iroh-mdns-address-lookup/ARACHNE-PATCH.md).

**Upstream status.** Current `main` still contains the stale-cache operation
([source](https://github.com/n0-computer/iroh-address-lookups/blob/a0cc9dbfc292ba338216a5df42bceba87c5fe541/iroh-mdns-address-lookup/src/lib.rs#L380-L403)).
Open [PR #15](https://github.com/n0-computer/iroh-address-lookups/pull/15)
replaces cached records when advertised endpoint data changes and directly
covers the functional patch. It has not merged or shipped.

**Exit condition.** PR #15 or an equivalent fix must merge and appear in a
release. Run `mdns_refresh` against that release and confirm both port refresh
and Cargo test isolation. This is the nearest complete fork exit.

### 4. Iroh Blobs

**Why the patch exists.** Arachne makes standalone tickets optional, disables
unused dependency defaults, exports the existing one-shot GC operation, limits
each file-store runtime to two workers, declares the Tokio features actually
used, and carries two build-only cleanup changes. It also points at the renamed
Bao fork. See the local
[`ARACHNE-PATCH.md`](../../vendor/iroh-blobs/ARACHNE-PATCH.md).

**Upstream status.** Current upstream keeps `iroh-tickets` and `genawaiter`
unconditional
([manifest](https://github.com/n0-computer/iroh-blobs/blob/e82cbdcbdac9a78033174aad55e3199b2cf4c0dc/Cargo.toml#L18-L44)),
keeps the GC module private and does not re-export `gc_run_once`
([store API](https://github.com/n0-computer/iroh-blobs/blob/e82cbdcbdac9a78033174aad55e3199b2cf4c0dc/src/store/mod.rs#L7-L20)),
and sizes each file-store runtime from Tokio defaults
([runtime construction](https://github.com/n0-computer/iroh-blobs/blob/e82cbdcbdac9a78033174aad55e3199b2cf4c0dc/src/store/fs.rs#L1397-L1408)).
[Issue #235](https://github.com/n0-computer/iroh-blobs/issues/235) tracks a
public manual GC API.

The GC path needs resolution before Arachne relies on an upstream API:
open [PR #240](https://github.com/n0-computer/iroh-blobs/pull/240) fixes a
mark/sweep race that can delete a referenced blob and changes the internal
`gc_run_once` contract; open
[#256](https://github.com/n0-computer/iroh-blobs/issues/256) reports that an
already-live `HashSeq` root can survive while its children are collected.

**Exit condition.** Upstream must ship a safe public one-shot GC API after the
#240 and #256 cases are resolved, configurable or bounded file-store workers,
optional tickets, and the dependency feature controls Arachne uses. The
unforked version must pass the greater-than-100 MiB transfer, verified resume,
authorization, revocation, and external-file checks. The HashSeq Clippy change
and copied-example error message are cosmetic and need not block exit.

### 5. Bao Tree

**Why the patch exists.** This fork only disables `genawaiter` default
features. Arachne uses its generator API without its procedural macros, so the
default chain adds the unmaintained `proc-macro-error` package without a
runtime benefit. There are no Bao, hashing, verification, or I/O code changes.
See the local [`ARACHNE-PATCH.md`](../../vendor/bao-tree/ARACHNE-PATCH.md).

**Upstream status.** Current 0.16.1 `main` still enables `genawaiter` defaults
([manifest](https://github.com/n0-computer/bao-tree/blob/2be9abd144783455606424424c29bd3a57f926f8/Cargo.toml#L20-L33)).
RustSec classifies `proc-macro-error` as unmaintained with no patched version
([RUSTSEC-2024-0370](https://rustsec.org/advisories/RUSTSEC-2024-0370.html)).
No upstream issue or PR for this feature selection was found.

**Exit condition.** Submit the one-line manifest change upstream. After a
release sets `genawaiter` to `default-features = false`, point Iroh Blobs back
to `bao-tree` and pass the resource transfer and resume checks. This is a small
upstream task, but it is not removable from the published dependency today.

### 6. Iroh Tor transport

**Why the patch exists.** Upstream uses `torut` for control-port commands and
onion keys. Arachne replaces that dependency with a bounded control client and
onion encoding, adds SAFECOOKIE authentication and ServiceID verification,
and caps the outbound stream cache. See the local
[`ARACHNE-PATCH.md`](../../vendor/iroh-tor-transport/ARACHNE-PATCH.md).

**Upstream status.** Current upstream `main` still directly depends on
`torut = "0.2"`
([manifest](https://github.com/n0-computer/iroh-tor-transport/blob/55b19c567f63e265d206f5a40369ab9597ce602e/Cargo.toml#L1-L26))
and imports its control and key APIs
([source](https://github.com/n0-computer/iroh-tor-transport/blob/55b19c567f63e265d206f5a40369ab9597ce602e/src/lib.rs#L20-L32)).
The newest `torut` release is
[`0.2.1`](https://crates.io/crates/torut/0.2.1), published in 2021. Its
dependency line includes `ed25519-dalek` 1.x and `curve25519-dalek` 3.x;
RustSec requires `ed25519-dalek >= 2`
([RUSTSEC-2022-0093](https://rustsec.org/advisories/RUSTSEC-2022-0093.html))
and `curve25519-dalek >= 4.1.3`
([RUSTSEC-2024-0344](https://rustsec.org/advisories/RUSTSEC-2024-0344.html)).
No upstream replacement issue or PR was found.

**Exit condition.** Upstream must remove `torut` and the affected Dalek chain,
implement SAFECOOKIE with fail-closed verification, verify Tor's returned
ServiceID, bound control replies and cached streams, and release against the
Iroh custom-transport API Arachne uses. The upstream release must then pass the
scripted control protocol tests, onion vectors, live ignored Tor test, and node
Tor transport check. Tor remains a supported Arachne transport throughout this
work.

## Recommended upstream order

1. Land mDNS PR #15 and retire the mDNS fork after release verification.
2. Submit Bao's one-line dependency feature change.
3. Upstream Iroh's residual restart behavior after #4512/#4525 ship.
4. Resolve Iroh Blobs GC correctness before proposing the public GC surface.
5. Track Gossip #161/#162, then propose the three host integration hooks.
6. Treat Tor as a maintained security fork until upstream replaces `torut` and
   matches the control-client hardening.

## Evidence ceiling

This is a source and metadata review, not an execution test or an external
audit. It compares Arachne's patch records and source with crates.io metadata,
official upstream repository source, issues, pull requests, and RustSec as of
the evidence date. No Cargo command was run. "No issue or PR found" means no
matching reference was located through repository issue/PR search and current
source history; it does not prove that no private or differently worded work
exists. Merge state can change after this snapshot, and every exit still
requires the stated Arachne regression checks against a released upstream
crate.
