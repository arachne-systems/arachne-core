
## Authenticated publication context

PublicationContext binds the workspace ID, local routing-policy revision, exact
Topic,16-byte publication ID and optional publisher sequence. `authenticated_bytes()` produces canonical
versioned bytes for the security owner. `packet()` carries an opaque ciphertext
behind a `DFAP` version1 marker and its publication ID for legacy contexts, or
version2 with an additional nonzero u64 sequence for new contexts. The sequence
is included under a distinct v2 AAD prefix. `unpack()` reconstructs
the expected context using the received Node frame's workspace/revision/topic.
It does not trust values extracted from unauthenticated MLS AAD.

The complete packet is bounded to16KiB. Header parsing is not authentication,
subscription or permission approval. Ciphertext authentication must succeed
before using the publication identity or sequence as accepted evidence, or delivering a payload. Retransmission
keeps the same ID and ciphertext; this helper is not a persistent ID allocator,
a retained outbox, or application-level duplicate ledger. Topic filters do not
create confidential subgroups within a shared MLS security context.
