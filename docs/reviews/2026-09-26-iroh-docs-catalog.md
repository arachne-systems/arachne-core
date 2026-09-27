# Iroh Documents for a durable Core catalog

## BLUF

Iroh Documents fits durable catalog replication **through a Core adapter**.
The standalone three-peer proof passed: a holder kept a manifest and content,
restarted, and served a third peer while the author was stopped. Direct
use of the default Documents and Blobs handlers does not preserve Core's
membership, removal, storage, or historical-access rules.

Keep the existing Core catalog and authorized resource operations for current
app work. Add Documents only behind those Core seams after the integration
gates below pass. The experiment is isolated from the production workspace.
It adds no PTT schema, SDK method, production dependency, or storage migration.

## Basis

- Core source: `integrate/wave1` at `94e30da`.
- Worktree: `arachne-core-night-docs`; branch: `codex/night-docs-qualification`.
- Reviewed the SDK note `2026-09-26-iroh-ptt-protocols.md` and official sources.
- Tested upstream Documents 0.101.0, Blobs 0.103.0, and Gossip 0.101.0.
- Documents source archive identifies commit
  `091e8cac47bbc49cdb84b0bfed227cc163b61dfe`.
- Iroh is 1.2.0 with Core's local restart patch. The experiment has a separate
  lockfile. It does not substitute upstream packages for Core's renamed forks.

## What the protocols supply

A Documents entry contains namespace, author, key, content hash, length and
timestamp. Its signatures bind the entry to a namespace and author key. The
metadata protocol reconciles sets of entries; Blobs supplies the referenced
bytes; Gossip announces updates. These are useful mechanisms for manifests
and holder claims. Receiving an entry does not prove that its content is
local. [Documents guide](https://docs.iroh.computer/protocols/documents),
[entry validation](https://github.com/n0-computer/iroh-docs/blob/091e8cac47bbc49cdb84b0bfed227cc163b61dfe/src/sync.rs#L421).

Blobs verifies content and requested ranges against their BLAKE3 hash. A hash
identifies bytes. It supplies neither a current holder address nor permission
to read those bytes. Core already uses this verification engine behind its
own resource admission. [Blobs guide](https://docs.iroh.computer/protocols/blobs),
[Core resource service](../../crates/arachne-node/src/resources.rs).

A read capability contains a namespace ID. A write capability contains the
namespace secret. These capabilities are separate from Core's MLS membership.
The default engine's incoming-sync decision uses whether a namespace is open
for sync and whether another sync is active. It has no Core membership input.
The lower-level `net::handle_connection` does expose an asynchronous
`(NamespaceId, PublicKey)` acceptance callback. That is a useful adapter seam;
it is not a complete revocation or storage solution.
[Capabilities](https://github.com/n0-computer/iroh-docs/blob/091e8cac47bbc49cdb84b0bfed227cc163b61dfe/src/sync.rs#L186),
[default sync state](https://github.com/n0-computer/iroh-docs/blob/091e8cac47bbc49cdb84b0bfed227cc163b61dfe/src/engine/state.rs#L90),
[connection acceptance](https://github.com/n0-computer/iroh-docs/blob/091e8cac47bbc49cdb84b0bfed227cc163b61dfe/src/net.rs#L100).

## Runnable qualification

Source and commands: [experiment README](../../experiments/iroh-docs-catalog/README.md).
The program has a 45-second deadline and uses loopback Iroh connections with
random local ports. It creates fresh temporary stores for every run.

| Check | Observed result |
| --- | --- |
| A writes a completion manifest and a 256 KiB object | B receives both exact blobs and the author's entries. |
| A stops; B closes and reopens its disk stores | B still has the metadata and bytes. |
| C imports the document through B with automatic content download disabled | Both metadata entries arrive; both blobs remain absent. |
| C fetches the blobs from B | Range verification completes; bytes, manifest fields and original author match. |
| C tries a write with only a read capability | Documents rejects the write. |
| B stops; C closes and reopens its stores | C reads its retained metadata and both blobs locally. |

The first harness run copied the data, then failed because the harness shut
Blobs down twice. Router shutdown already closes the store. After removing
that second call, the full scenario passed in 457 ms with 49,488 KiB maximum
resident memory. This was a harness correction, not a Core or upstream fix.
The initial receipts are `/tmp/h1-docs-first-run.log`,
`/tmp/h1-docs-run2.log`, and `/tmp/h1-docs-run2-time.log`.

This proves protocol retention and transfer for the stated fixture. It does
not prove Core authorization, member removal, crash recovery, garbage
collection, a large catalog, relays, mDNS, tablets, or mobile background work.
The two restarts are graceful close and reopen within one process.

The final locked build passed. Ten consecutive qualification runs passed,
with elapsed times from 0.672 to 0.869 seconds. `rustfmt --check` passed.
Clippy with all experiment targets and `-D warnings` passed in 19.50 seconds.
The checked-in [receipt](../../experiments/iroh-docs-catalog/evidence.json)
records every run and its evidence limits.

## Existing Core seams

| Core seam | Reuse and limit |
| --- | --- |
| `CatalogEntry { key, payload, tombstone }` | Keep the generic envelope. The application owns payload meaning. The topic names the catalog. |
| Current publications and current-view recovery | Use existing author, selector, replacement, expiry and holder checks for the current bounded view. There are 64 current values and 64 selections. |
| Retained publication recovery | Preserve author and holder as separate identities. It retains 32 packets per topic, a 512 KiB epoch log, and a 192 KiB publisher snapshot budget. These bounds are not a durable object-count policy. |
| `Client::resource(ResourceRequest)` | Keep native prepare, fetch, poll, cancel, revoke and clear. H4 already exposed the typed Core seam at this baseline; the older SDK review predates that work. |
| Native encrypted records and candidate adoption | Keep canonical accepted catalog state here. Publish or expose a received catalog change only after its native transaction commits. |

Sources: [catalog envelope](../../crates/arachne-delivery/src/catalog.rs),
[current view](../../crates/arachne-delivery/src/current.rs),
[retained log](../../crates/arachne-delivery/src/lib.rs),
[publisher log](../../crates/arachne-delivery/src/publisher.rs),
[typed resources](../../crates/arachne-runtime/src/client/resources.rs),
[native persistence](../../crates/arachne-runtime/src/persistence.rs).

## Proposed Core adapter

This is an integration design, not an accepted public interface.

### Model and ownership

Core owns a catalog scope, accepted author identity, object identity, resource
reference, audience, retention state and verification status. A manifest's
body stays opaque to Core. A holder claim identifies the member which can
serve an object. It does not change the object's author or prove completion.
The application supplies any domain-specific completion evidence.

Use immutable manifest keys derived from a stable object ID. Give each holder
its own record. Query holder records per author; a global latest-per-key
query must not let one holder replace another holder's claim. Keep withdrawal
and expiry explicit. A local eviction first withdraws the holder claim, then
revokes active grants, then deletes content. A catalog tombstone does not
promise erasure of other peers' copies.

Documents author keys need a Core-verified binding to member identity. A
namespace write key, a Docs timestamp, or the ability to send a Docs entry
must never establish Core authority. Keep the binding and any private keys
inside native protected storage. The Docs signature remains useful for
replication provenance after that binding is checked.

### Data path

1. The app uses the SDK's generic catalog/resource operations. It never gets
   a raw Docs capability as a replacement for workspace access.
2. Core checks membership, topic policy, audience and branch send state.
   A local catalog mutation enters a native candidate and commits before it
   becomes an advertised Docs entry.
3. Core resolves a namespace to one catalog scope. On every incoming sync,
   it checks the authenticated endpoint against the accepted membership and
   policy for that scope. A private namespace ID alone cannot pass this gate.
4. Documents reconciles opaque metadata into a bounded staging area. Core
   checks author binding, scope, object identity, expiry and payload proof.
   Core saves accepted rows in its encrypted record transaction before it
   exposes them to SDK readers. Unverified rows cannot become authoritative
   current values or cause an application action.
5. Set Documents automatic downloads to `NothingExcept([])`. Fetch manifest
   bodies and large objects through Core's current member/recipient-bound
   resource grants. Keep the Docs index, local byte presence and successful
   content verification as distinct states.
6. On membership or policy change, cancel affected syncs and transfers,
   remove their live Gossip interests, recheck queued records, and stop
   outgoing work when the local branch is orphaned or send-quarantined.
   Continue permitted receiving under the existing Core lifecycle.

An Iroh-only design can use the Documents ALPN with a Core-owned protocol
handler. Adding that ALPN does not authorize it. The adapter must also reuse
Core's dial budgets, workspace Gossip admission and lifecycle cancellation.
The existing resource path remains inside Core's data ALPN with its grants.
No alternative socket transport is required.

### Durable state

The default Documents store is a concrete redb-backed store. Its public
constructors select memory or a file; its database constructor is private.
Its API does not accept Core's encrypted `StorageProvider` transaction.
`SyncHandle` can export signed entries and import remote signed entries, which
could support rebuilding a replica from native canonical rows. That path
still needs a bounded implementation and a crash test. It is not proved by
this experiment. [Store constructors](https://github.com/n0-computer/iroh-docs/blob/091e8cac47bbc49cdb84b0bfed227cc163b61dfe/src/store/fs.rs#L112),
[signed-entry interface](https://github.com/n0-computer/iroh-docs/blob/091e8cac47bbc49cdb84b0bfed227cc163b61dfe/src/actor.rs#L389).

Prefer native encrypted records as the source of accepted catalog state, with
Documents as a rebuildable index and sync mechanism. Qualify either an
upstream storage adapter or the signed-entry rebuild path. Do not commit a
second unprotected database containing namespace/author private keys. Do not
expose a live replica row before its native durable adoption. If a bounded
index cannot satisfy these rules, retain the current Core primitives and
leave Documents disabled.

## Exact integration blockers

| Blocker | Required change or proof |
| --- | --- |
| Different Rust package identities | Docs 0.101.0 takes upstream `iroh_blobs::api::Store` and `iroh_gossip::net::Gossip`. Core uses renamed Arachne forks. Rebind Docs to those forks in a reviewed dependency change, then prove one Iroh identity and the intended Gossip/Blobs implementations in Cargo metadata. Version-family alignment alone is insufficient. |
| Default admission is not Core authority | Add the namespace-to-scope authorization adapter. Prove removed and unrelated endpoints cannot sync or fetch, including with an old valid ticket. |
| Active work after removal | Add scope cancellation for existing Docs syncs, Gossip interests and queued downloads. A one-time connection check is insufficient. |
| Docs author identity is independent | Bind authors and accepted entries to Core identity and policy. Reject author substitution, replay from a losing branch, and stale authority before SDK visibility. |
| Independent persistence | Couple accepted rows and keys to native encrypted records and save/adopt ordering. Prove crash points before and after commit. |
| Blob retention is independent | Protect retained bytes from garbage collection; revoke serving before eviction; do not advertise a holder until bytes are complete and durable. |
| Historical access is different | Preserve Core's historical audience and receive-window rules until a separate durable object policy is defined. |
| Resource limits | Set row, byte, query, staging, sync and per-peer budgets. The two-row proof does not establish large-catalog capacity. |

Sources for the dependency blocker: [Docs builder types](https://github.com/n0-computer/iroh-docs/blob/091e8cac47bbc49cdb84b0bfed227cc163b61dfe/src/protocol.rs#L94),
[Core dependency pins](../../crates/arachne-node/Cargo.toml),
[Gossip patch contract](../../vendor/iroh-gossip/ARACHNE-PATCH.md),
[Blobs patch contract](../../vendor/iroh-blobs/ARACHNE-PATCH.md).

## Historical access decision

Core currently checks that a recovery peer and original author are current
members. It rejects epochs outside the receive window. The publisher log
also excludes members admitted after the requested epoch.
[Recovery policy](../../crates/arachne-runtime/src/ops/recovery.rs),
[signature authority](../../crates/arachne-security/src/recovery.rs),
[publisher history](../../crates/arachne-delivery/src/publisher.rs).

A durable catalog cannot extend those rules merely by keeping old ciphertext.
It must not retain expired private epoch keys to make that ciphertext readable.
A separate durable object record can be designed, but its audience and author
proof must be explicit.

Question for the owner before that work: should a newly admitted member see
objects completed before it joined, and should objects remain shareable after
their original author leaves? Current recovery denies those cases. This
qualification preserves that behavior. The current-member A/B/C scenario
needs no broader historical access decision.

## Next production gate

Add one Core-owned adapter slice, with failing tests before implementation:

- Existing authorized members A, B and C: A publishes; B keeps the object;
  A stops; B restarts; C catches up through the SDK and verifies provenance.
- An outsider and a removed member both hold old Docs read/write capabilities.
  Reject their metadata requests, writes and content fetches.
- Remove C while metadata sync or a large resource transfer is active. Stop
  protected delivery and reject queued results under the old policy.
- Kill the process before and after the native catalog commit. Restore only
  accepted rows, keys and honest holder state.
- Publish two independent holder claims, withdraw one, expire another, and
  run garbage collection. Metadata must not imply bytes remain available.
- Keep a long-offline member outside the receive window. Reject unsupported
  history; do not silently reuse expired keys or grant a new history policy.

Merge the experiment and review as evidence. Keep the production adapter,
dependency and persistence changes separate until these gates pass.
