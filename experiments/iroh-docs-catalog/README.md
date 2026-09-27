# Iroh Documents catalog qualification

## BLUF

This local program checks that a holder can keep document metadata and blob
content, then serve another peer while the author is stopped. It uses three
Iroh endpoints on loopback and persistent stores. It is a protocol experiment.
It does not implement or test Core workspace authorization.

The experiment has its own Cargo workspace and lockfile. The production
Core workspace does not depend on it. See the
[integration review](../../docs/reviews/2026-09-26-iroh-docs-catalog.md)
for the required Core adapter and open gates.

## Run

From the Core repository root:

```sh
flock ~/development/worktrees/.cargo-build.lock nice -n 19 env \
  CARGO_BUILD_JOBS=4 CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  CARGO_TARGET_DIR="$PWD/target" \
  cargo +1.98.0 build --locked \
  --manifest-path experiments/iroh-docs-catalog/Cargo.toml
nice -n 19 taskset -c 0-3 target/debug/iroh-docs-catalog-qualification
```

The program exits with an error if a check fails. Each network wait has a
10-second deadline. The whole program has a 45-second deadline. The last
output line is a JSON receipt. Temporary data is deleted at exit.

## Checks

1. A publishes a generic completion manifest and 256 KiB of content.
2. B receives the original author's entries and both complete blobs.
3. A stops. B closes all protocol handlers, then reopens the same disk stores.
4. C synchronizes only metadata from B. Both blobs are still absent at C.
5. C fetches both blobs from B with standard Blobs range verification. It
   checks exact bytes, the manifest fields, and the original entry author.
6. C cannot write with a read capability.
7. B stops. C closes and reopens its disk stores, then reads both local blobs.

## Evidence limits

Restarts are graceful close and reopen in one process. This does not prove
crash recovery, a mobile background lifecycle, or a power-loss boundary.
The program uses no relay, mDNS, tablet, or external peer. It measures two
catalog rows and 256 KiB of content, not a large catalog.

The raw Documents and Blobs handlers in this program have no Core MLS gate.
Content is a public synthetic fixture. Namespace capability checks are not
workspace membership checks. Garbage collection, eviction, expiry, member
removal, and concurrent holder claims need separate integration tests.

The pinned upstream Documents, Blobs and Gossip packages are used together.
Only Iroh itself and its netlink dependency use the same local patches as
Core. This does not resolve Core's renamed Blobs/Gossip package integration.
