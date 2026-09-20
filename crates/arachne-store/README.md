# Atomic encrypted records

`arachne-store` provides a local SQLite record store for the portable runtime.
It has no production dependency on MLS, ATAK, networking or payload formats.
The host supplies a private directory, a protected root key and an expected
workspace scope. One store owner holds SQLite's exclusive connection lock.

`Store::open(path, root, scope)` creates a new store only at a new path, or
authenticates an existing store. `keys(prefix)` enumerates authenticated record
names, and `get(key)` reads a record. `commit(revision,
changes)` atomically puts/deletes records and advances the revision. A change
with `None` deletes; an empty value remains a present record. Duplicate keys and
stale revisions fail. After an uncertain I/O outcome, close/reopen before doing
more work. Domain state may be adopted and packets emitted only after commit.

Only changed ciphertext rows and the authenticated head are rewritten. There is
no fixed record-count limit. Each key is at most 1 KiB and each plaintext record
at most 1 MiB; these are input budgets, not workspace population settings. A
serializer must split larger logical values into records and commit their
references together. Chunking is not implemented by this generic store.

## Protection and consistency

SQLite handles transactions with DELETE journals and FULL synchronous mode.
Values are encrypted before they reach SQLite. A storage key is derived with
HKDF-SHA256: salt `data-fabric/record-store/v1`, input root key, info workspace32.
AES-256-GCM uses a fresh OS-random nonce12 for each encryption. Record AAD is
`data-fabric/record/v1`, workspace32, kind1, key length u32, key bytes. Kind 0 is
the head; kind 1 is a value. Packets contain nonce12 and ciphertext/tag16.

The encrypted head contains revision u64 and SHA-256 of the sorted key/digest
index. Its hash input is `data-fabric/record-index/v1` followed by each key's
u32 length, bytes and ciphertext digest32. Reopen rebuilds and checks this index;
reads check the selected ciphertext against it. Partial row rollback, deletion
and substitution therefore cannot masquerade as a complete accepted transaction.
Unexpected schemas/triggers and a missing head are rejected. An existing damaged
file is never silently reinitialized.

Keys, record lengths and database activity are not hidden. The caller must avoid
putting private presentation data in keys. Whole-database rollback remains
undetectable without an external freshness anchor, as with the legacy encrypted
snapshots. OS/device compromise, physical secure erasure, CSPRNG failure and
power-loss behavior are not proven by the tests below.

The current index uses O(record count) memory and copy/hash work per transaction;
reopen hashes the retained ciphertext. This is an explicit measurement ceiling,
not a count restriction. Improve the index only if measured workloads require it.

## Executed gate and current integration boundary

Run `cargo test -p arachne-store -- --nocapture`. The two tests cover:

- A real MLS admission's state, commit and Welcome: forced failure at the second
  SQL write, reopen with all old records, then a complete successful transaction
  and a matching restored/joined workspace.
- 128 incremental records; unchanged ciphertext preservation; deletion, empty
  values, stale revisions, duplicate changes and oversized-record rejection.
- Key/workspace binding, mixed old/new rows, missing heads, unexpected triggers,
  exclusive ownership, and a plaintext-marker scan of the DB and live rollback
  journal.

`python3 scripts/check-store-android.py --output evidence/NEW.json emulator-5582`
builds and executes the same native tests on Android, verifies the uploaded
binary hash, and removes its isolated temporary files. It does not install a
plugin, restart ATAK or modify saved workspaces. The preserved host and Android
receipts are `evidence/incremental-store-*`.

The runtime session does not yet use this store. The original admission gate
stores an existing sealed workspace as one value to validate atomic composition.
The separate `arachne-runtime --test record_storage` composition now uses native
security records and exercises 100-member persistence. Session/JNI migration must
still preserve legacy files and current save-before-emission invariants.
