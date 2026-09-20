# Portable delivery state

`PublisherLog` indexes encrypted publications for one workspace, author and
cryptographic epoch. It assigns a monotonically increasing publisher sequence,
keeps bounded per-topic records and preserves eviction watermarks. It does not
parse application payloads, authenticate callers, write files or own transport.

`select(after, through, topics)` returns the complete retained selection within
`(after, through]`, in publisher order. The exact-topic selection is canonically
hashed into a `RecoveryRequest`; `RetainedRange::sign_offer` uses the existing
security owner to sign that exact record set. Topic authorization must happen
before selection or disclosure. Required sparse-progress topics must be included
explicitly by the recovery protocol; the index does not infer them.

`RangeError` distinguishes invalid requests, unavailable history and responses
exceeding the offer packet limit. A valid empty selection returns a retained range
with zero records and is signed like any other complete selection. The `Empty`
error remains only for decoding legacy advisory wire responses. No oversized or incomplete range
is silently truncated into a successful offer. Watermarks are per topic, so losing
unselected feed history does not automatically invalidate retained chat history.
A watermark can conservatively reject an old range rather than invent coverage.

Bounds are 64 observed topics, 32 retained packets per topic and 512 KiB of weighted
retained data. The byte budget can evict the globally oldest record across topics.
Evicted topics remain represented, even with no packets left; their history must
not be mistaken for a topic that never had publications. The index refuses new
topics once its metadata bound is reached. Offers remain capped at 32 packets.
These are development bounds, not a measured scaling envelope.

Use `append` only for new publications. Retries reuse retained ciphertext and its
original publication identity. Duplicate detection covers the retained window,
not every ID ever generated. A retransmission after eviction cannot safely be
re-created by restoring old sender state.

## Retrieval authorization

`authorized_range(owner, policy, requester, query)` checks the expected
workspace/author/epoch, current MLS membership, accepted routing policy revision,
reader access to every selected topic and this author's current publish grant.
The requester must come from authenticated transport, never a peer ID supplied
inside the request. The caller must provide current accepted policy and membership.
The method does not install subscriptions or derive permission from interest.

Denied requests receive no history availability distinction. Only authorized
requests reach selection and its invalid/unavailable/too-large outcomes.

An object inbox may also retain up to four exact publisher-signed range replies
with a caller-supplied expiry. A current authorized holder can replay only the
identical query/reply pair; restore revalidates the original publisher signature,
and current membership and routing policy are checked again before disclosure.
The holder does not sign as the author or claim broader coverage. An expired or
missing retained pair returns unavailable. This is a bounded repair primitive,
not automatic holder discovery or a replication policy.
This interface serves the original publisher's own index; it does not authorize
an arbitrary holder to impersonate the author. The low-level `select` interface
remains for trusted local use and has no authorization check of its own.

Real-MLS tests use the authorized selection to sign and decrypt an offer, and
reject nonmembers even with a stale routing grant, wrong scope/epoch/revision,
reader revocation and publisher revocation. An unreadable evicted topic produces
denial rather than revealing missing history. Granting read access makes the
unavailable result observable. The native recovery control dispatcher uses this gate.

## Bounded recovery wire format

`RangeQuery::to_wire/from_wire` encode exact-topic requests. `wire::serve_range`
authorizes and encodes a signed retained selection; `wire::verify_reply` validates
all records and their ordered hashes without advancing MLS. Its `VerifiedRange`
exposes immutable packets and an origin check for each later decrypted message.
A caller must still stage decryption and persist the matching receiver state.

All integers use big-endian encoding. A topic uses a u8 byte length followed by
canonical ASCII bytes. Queries require strictly sorted unique topics.

| Record | Layout |
| --- | --- |
| Query | `DFRQ` + version1, workspace32, author32, epoch u64, policy revision u64, after u64, through u64, topic count u8, topics |
| Successful reply | `DFRP` + version1 or2, status0, offer length u16, signed offer bytes, packet count u8, ordered packets |
| Packet | Original publication policy revision u64, topic, publication ID16, sequence u64 (version2 only), ciphertext length u32, ciphertext |
| Rejection | `DFRP` + version1, status only: 1 denied, 2 invalid, 3 unavailable, 4 empty, 5 too large |

Limits match the existing control channel: 32 KiB request and 128 KiB reply.
Selections remain bounded to 64 topics and 0–32 packets. Zero packets require a
valid signed zero-count offer; a bare empty status is not equivalent. A selection that exceeds
the reply byte limit returns `TooLarge`, never truncated success. Decode rejects
trailing/truncated data, unknown statuses, unexpected topics and repeated IDs.
The signed offer binds the locally expected range/selection and ordered packet
contexts/ciphertexts. If any selected record has authenticated publisher order,
the successful reply uses version2 and adds a u64 after each packet ID: zero means
legacy unknown order, nonzero is the authenticated sequence. Version1 replies
remain readable and carry no authenticated sequence. Version2 sequences must be
strictly increasing where present and fall within the locally requested range.
Changing an order or inventing one for a legacy record fails packet-set verification.
The writer uses version1 for entirely legacy or empty selections; rejection and
cutoff formats are unchanged.

Rejections are advisory transport results, not signed statements of coverage.
They cannot advance a cursor, delete retained keys or establish empty history.
The transport caller must bind replies to its request and peer. Successful
verification likewise does not establish latest-data freshness or cursor origin.

Host checks exercise canonical/bounded framing, omission, reordering, corruption,
oversize rejection and real MLS decryption. A separate real-Iroh check transfers
and verifies adopted retained ciphertext between admitted peers with a test-supplied
policy and handler. The native dispatcher now also serves these records through
its single control poller using the node's actual current routing policy. Native
host tests cover that path and policy revision/revocation denial. Cutoff discovery is integrated in the native/Kotlin runtime. Verified range
progress and staged native adoption are implemented. Kotlin does not yet schedule
range recovery; automatic ordering and holder replication remain unimplemented.

## Persistence contract

Clone the index when staging a publication with a disposable security owner. A
successful append and encryption must commit as **one authenticated atomic host
record** before either owner is adopted or ciphertext is released. The snapshot
codec is deterministic and bounded, but contains sensitive metadata alongside
ciphertext; it is not an authenticated file format by itself. Restore accepts an
expected scope from accepted security state and validates encoding/limits.

`PublisherLog::seal(owner, key)` now produces one authenticated `DFWB` version 1
record after checking workspace, author and epoch against the security owner.
`restore_sealed` authenticates both components and validates the decoded index
against the restored owner before returning either. The security module treats
its attachment as opaque; it does not depend on delivery or payload schemas.

The outer record reuses the existing AES-GCM implementation with a distinct
version marker authenticated with workspace and endpoint scope. Its encrypted
body contains a length-prefixed existing security snapshot and length-prefixed
attachment. Each length is a big-endian u32. Attachments are limited to 528 KiB;
the old 24 KiB security plaintext limit remains unchanged. Existing `DFWS`
snapshots remain readable by their original API. Random nonces make resealing
nondeterministic. This authenticates a pair, not its age or semantic correctness.

The real-MLS test restores a combined encrypted record in RAM, checks scope and
tamper rejection, then verifies and decrypts its selected retained publications.
It does not prove a disk transaction, crash atomicity or freshness against rollback.
The native runtime now pairs this index with routed publication candidates,
using binary snapshot transfer and Android's atomic save/readback before adoption.
Receives and low-level security operations preserve an existing index. The index
covers routed publications only; raw security-test messages have no topic/index
entry. A membership epoch transition drops this prototype's old-epoch index.

Existing DFWS workspaces acquire an index on their first routed publication after
activation. This starts a local retention history and does not establish coverage
for earlier publications. A corrupt DFWB record fails closed; it never falls back
to an empty index. Pre-retention clients cannot read the new record family;
downgrading must not restore an obsolete security snapshot. Runtime receiver progress/adoption is not exposed yet. Its
protocol must state activation and unavailable history explicitly before making
coverage claims.

Host tests close a session before adoption and restore the complete candidate,
checking identical retained ciphertext and a new sequence/ciphertext on the next
publication. This models loss of process ownership with records in RAM, not disk
or power-loss behavior. The emulator restart harness separately tests saved record
migration and controlled restarts through the normal controller and storage path.

Android process-death tests now cover before-save, partial AtomicFile writes and
after-save/before-adoption in isolated storage with records over 128 KiB. The
partial-write case exercises the Android primitive directly; no power-loss or
network-release/callback crash claim follows. See the storage-crash receipts.

Next: automatic range scheduling, holder discovery and safe receipt reclamation;
network-release/callback failure checks remain. Publisher-log time eviction,
old-epoch history, private audiences and attribute selectors are not implemented.

## Receive evidence and combined persistence

`receive::ReceiveJournal` distinguishes an exact prior authenticated publication
from an unknown packet or a conflicting reuse of author/publication identity.
Callers must verify the recovery offer before using its author to look up receipts,
and authenticate/decrypt and verify origin before recording a new receipt.
An unknown decryption error is not duplicate evidence: discarded keys and replays
can produce the same MLS error. Records do not prove application callbacks or reads.

`PublisherLog::seal_with_receipts` seals security state, publisher history and
receive evidence together. `restore_with_receipts` authenticates the whole record
and validates both delivery components against the restored owner before returning
any of them. The host must atomically save/read back the entire sealed candidate
before adoption. This library performs no disk writes.

The opaque attachment layout is `DFDL` + version 1 + publisher length (u32 big
endian) + DFRL publisher snapshot + DFRR receive snapshot. Existing DFWB encryption
and its 528 KiB attachment bound remain unchanged. The combined size must fit;
individually valid components can exceed that shared budget and are rejected
without eviction or mutation. Receive records are capped at 256 entries. The v2 journal also holds at most
64 recovery-progress entries and is capped at 25,137 bytes.
This is an explicit prototype ceiling, not a throughput claim.

The new restore method accepts legacy DFRL attachments while preserving their
publisher history and initializing an empty receive journal. Empty means no
retained receipt evidence, not proof that earlier messages were never received.
Legacy `restore_sealed` rejects DFDL attachments; it must not restore only the
publisher and silently lose receipts. DFWS-only migration is still a host concern.

Real MLS checks recover seven messages after skipping one previously received
message, while preserving the receiver's own retained outgoing publication across
the same sealed-state restore. Codec tests cover authenticated malformed framing,
wrong scope/epoch, ciphertext tampering and aggregate capacity rejection.
These are host RAM restoration tests. The combined receipt format is not activated
in Android yet: ordered receive progress and safe receipt reclamation remain gates.

## Signed empty selections

A requested nonempty publisher interval can contain no publications on selected
topics. The publisher checks authorization, head and retained eviction watermarks
before signing this empty set. Unknown/future history and evicted selected history
must not become empty coverage. Unselected history eviction does not invalidate
an otherwise covered selection.

The existing v1 offer and successful reply formats now permit packet count zero;
all scope, range, selection and signature checks remain mandatory. Earlier readers
reject zero-count success, so mixed versions fail closed rather than treating an
unsigned advisory as coverage. Legacy status 4 remains a rejected/advisory result.
An attacker cannot erase a nonempty response: its signed count and packet hashes
still require all publications. An authorized dishonest publisher can sign a false
claim; these signatures establish authorship, not independent completeness.

Signed empty coverage can advance staged recovery progress, committed only with
the matching receiver snapshot. It neither advances an MLS sender generation nor
supplies skipped keys, establishes freshness,
changes permissions, or authorizes forgetting receipt evidence by itself.


## Authorized cutoff discovery

`wire::CutoffQuery` requests the adopted publisher index head for an exact topic
selection. It uses `DFCQ` + version1, workspace32, author32, epoch u64, policy
revision u64, nonce32, topic count u8 and canonical sorted unique topics. Counts
are 1–64, with the same topic encoding and 32 KiB request bound as range queries.

`serve_cutoff` shares range retrieval's current membership, scope and per-topic
reader/publisher authorization checks. Only then does it sign the adopted head
with the cutoff signature domain. A missing/inactive index or rejected/malformed
request receives the generic DFRP v1 denial. `verify_cutoff_reply` returns a verified
head or `None` for that advisory denial; denial is never head zero. Other advisory
statuses, invalid framing and wrong request/signature are errors.

The native single control poller routes DFCQ before admission parsing, under the
same session and routing-policy locks as range serving. Pending adoption prevents
control polling. There is no separate head registry. This serves the original
publisher's own current-epoch index, not an arbitrary replica's claimed head.
The head is global within that publisher/workspace/epoch and can reveal publication
activity on unselected topics; it conveys no other workspace membership or payload.

The native/Kotlin requester creates and consumes a fresh nonce. It observes the
cutoff; runtime adoption of verified range progress remains separate work. A signed head alone authorizes no cursor advance, key
loss, receipt reclamation or application delivery. The index can contain eviction
watermarks; request the selected ranges to learn whether history is available.


## Staging a recovered range

`ReceiveJournal::stage_recovery(owner, key, publisher, query, reply)` verifies the
complete signed wire reply against the current owner and locally established query,
then decrypts only in a disposable receiver owner. It stages exact receive evidence
and preserves the receiver's outgoing publisher history. Unknown decryption errors,
conflicting publication identities, origin mismatches and capacity failures abort
the candidate; no active owner, receipt or publisher state changes. Advisory
rejections remain typed `RecoveryStage::Rejected` outcomes.

`RecoveryStage::Prepared` contains the candidate owner, receive journal, one sealed
combined snapshot, newly authenticated publications with their original routing
contexts, and the count of exact prior receipts skipped. The host must atomically
save/read back that snapshot before adopting state or releasing publications. The
public candidate fields are a trusted host seam, not a cryptographic enforcement
of disk persistence. Plaintext publications are not a durable application outbox;
a crash after saving and before an application callback still needs separate work.

The query's range and local topic authorization remain host responsibilities.
Staging is not proof that an author honestly retained every publication, that the
range is current, or that earlier live traffic did not discard needed MLS keys.
The journal stages contiguous progress per author and exact topic selection;
safe automatic receipt reclamation remains unimplemented.
Native range fetching/adoption and ordering live traffic before ratchet advancement
remain integration gates; this staging helper is not active in the ATAK runtime.

Real MLS tests cover a signed reply whose later ciphertext is invalid, followed
by a successful valid retry using the same active owner; capacity rejection after
decryption; seven new publications with one exact prior receipt; preserved outgoing
ciphertext across combined restore; and a repeated covered range returning `AlreadyCovered` without a new
candidate or publications. Lost keys remain errors even with a valid signed offer.


## Persisted recovery progress

The journal binds progress to its workspace/epoch and a pair of author ID and
canonical exact-topic selection digest. `progress` returns None when no verified
range has been accepted for that pair; it does not infer coverage from existing
live receive records. The first staged range must start at publisher index zero,
which covers that retention index only, not pre-activation or old-epoch traffic.

After full reply verification, `stage_recovery` requires each advancing range to
start exactly at the previous progress position. Gaps and partially overlapping
advances fail. A range already wholly covered returns `AlreadyCovered`, with no
new candidate or publications; that result is not an application delivery receipt.
Changing author or exact selection starts independent progress. Policy revisions
remain subject to current host authorization rather than resetting received history.

Only successful complete staging updates the candidate progress before sealing.
That includes a signed empty selection. Unsigned Empty remains advisory and does
not advance anything. The active journal changes only when the host atomically
saves/read backs and adopts the candidate with its receiver security state.

DFRR v2 appends a u16 progress count after the existing receive records, followed
by sorted unique author32/selection32/through-u64 rows. All integers are big-endian;
through must be nonzero. The decoder enforces the 64-entry bound, exact lengths,
canonical order and no trailing data. DFRR v1 remains readable with its records
preserved and no invented progress. Earlier readers reject v2. Neither version
adds rollback protection outside the authenticated host record.

No receive records are reclaimed yet. A stored progress cursor alone cannot safely
classify legacy late live packets that carry no publisher sequence. New sequenced
packets provide ordering evidence after authentication, but ordered live reception,
safe reclamation and ratchet recovery across large skipped streams remain required
before automatic range recovery is activated in the plugin. Native atomic adoption
is implemented; the application callback handoff remains volatile.


## Authenticated publisher order and snapshot compatibility

A new publication can carry `PublicationContext.sequence`; `append` requires it to
match `head + 1` before changing the log. Native senders assign this number before
MLS protection and stage the counter, ciphertext and security owner together.
A missing sequence denotes legacy AAD, not an instruction to invent one.

Snapshots with any sequence-bearing retained record use DFRL version2. Each record
adds a byte after its existing index sequence: 0 preserves legacy context, 1 binds
that same sequence into context AAD. Other markers reject. DFRL version1 remains
readable, preserving original contexts and ciphertext. Mixed histories can thus
migrate without re-encryption or altering receipts. Combined DFDL/DFWB outer
formats and bounds are unchanged. Old readers reject DFRL2; no downgrade is safe.

This exposes authenticated order for subsequent receiver coordination. It does
not supply a live reorder buffer, receipts reclamation, cryptographic-generation
bridging or a durable application outbox.

## Catalog entries

`catalog::CatalogEntry` is the shared envelope for workspace catalog metadata.
It binds a stable 32-byte entry key to an opaque bounded adapter payload and an
optional tombstone. The surrounding current-value record supplies the
workspace, authenticated author, replacement, expiry and recovery semantics.
The topic names the catalog namespace; feeds and resources intentionally keep
separate payload schemas and availability rules. A catalog entry is discovery
metadata, not a permission grant or proof that its subject is reachable.
