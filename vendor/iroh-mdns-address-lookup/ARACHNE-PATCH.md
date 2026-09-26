# mDNS address refresh

## BLUF

Keep the newest address for a known peer. Without this change, a later lookup
can return the peer's old UDP port after an app restart.

Upstream: `iroh-mdns-address-lookup` 0.5.0, repository
`https://github.com/n0-computer/iroh-address-lookups`, commit
`a0cc9dbfc292ba338216a5df42bceba87c5fe541`.
Crates.io archive SHA-256:
`cad3dfcaddd5c3681bf0a42606498fc6e8891de793408dfbc46a9fbe76f370b3`.

## Changes from the archive

- `src/lib.rs`: replace `entry.or_insert(peer_info)` with
  `entry.insert_entry(peer_info)`. The actor already detects changed peer
  information. It must replace the occupied cache entry, too.
- `Cargo.toml`: rename the package to `arachne-iroh-mdns-address-lookup` and
  set version `0.5.0-arachne.1`. The Rust import name stays unchanged.
- `README.md`: add the fork notice. Add this patch record.
- Add the upstream MIT and Apache-2.0 license texts from the commit above.
  The published archive omitted them. Keep the upstream original manifest,
  examples, and all other source unchanged. Omit the package-local lockfile
  and Cargo registry bookkeeping files.

No wire, transport, authentication, or API change. Core depends on this named
path fork directly, so the SDK and app use the same fix.

## Check

`crates/arachne-node/tests/mdns_refresh.rs` advertises one peer on port 11111,
then on port 22222. It observes the update before it starts a new lookup.
Upstream returns 11111 (RED, 1.55 s). The fixed cache must return only 22222.
Remove this fork when an upstream release passes this check.
