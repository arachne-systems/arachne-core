# Arachne dependency remediation

Base: published `netlink-packet-core` 0.8.2, unmodified package name/version.
Source: https://static.crates.io/crates/netlink-packet-core/netlink-packet-core-0.8.2.crate
Archive SHA-256: `b897d7bd4f0af82e68d40d0344cf37e97f9c97ddf74a098de3e4da05e96ca395`.
Published VCS revision: `571d8bb5fa1dbaa875e8aede3f214c87f70b955b`.
Original MIT license and `Cargo.toml.orig` are retained verbatim. Package-local
lockfile/registry bookkeeping are omitted; the consuming workspace lockfile
is authoritative, as for the other Arachne vendor packages.

Changes:

- Replace the unmaintained `paste` dependency with the real published `pastey`
  0.2.3 package and change its two imports. Preserve the exported `paste!` name,
  all buffer/getter/setter macros, parser signatures and wire behavior.
  https://docs.rs/pastey/0.2.3/pastey/ describes the maintained replacement.
  Archive: https://static.crates.io/crates/pastey/pastey-0.2.3.crate
  SHA-256: `2ee67f1008b1ba2321834326597b8e186293b049a023cdef258527550b9935b4`.
- Remove upstream's obsolete `RUSTSEC-2024-0436` ignore from `deny.toml`.
- Add a buffer/accessor/parser compatibility regression to `src/macros.rs`.

Upstream 0.9.0 removes `buffer!` and related macros in
https://github.com/rust-netlink/netlink-packet-core/commit/aa5e7ed . Backporting
that deletion would break the locked `netlink-packet-route` 0.31.0 consumers.
This substitution keeps the 0.8 API; it does not relabel `paste` or suppress its
advisory. Remove the patch when the transport parents support the upstream API.

Run the existing packet tests plus the regression with
`cargo +1.98.0 test --manifest-path vendor/netlink-packet-core/Cargo.toml --lib`
from the root. This standalone test uses upstream's unchanged old example dev
dependency (route 0.13.0), which itself still pulls `paste`; it is absent from
both consuming workspace graphs. Keep that generated test lockfile/build output
under ignored `.cache/`, not in the source package. The production route 0.31.0,
netwatch and Iroh consumers are checked through the root locked workspace.
