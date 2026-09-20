# Arachne bounded resource transfers

Upstream: iroh-blobs 0.103.0, crates.io archive SHA-256
`5be50b0e2d0a9ba65cee4e0dfb708b3704e02ad12bd4c14c6307e94245943126`.
MIT/Apache-2.0 licenses and published source are retained. Package-local lockfiles
and Cargo registry bookkeeping are omitted; the root lockfile is authoritative.
Trailing whitespace and extra EOF blank lines in upstream documentation and
workflow/configuration files are normalized.

Small host-integration changes, with no Bao, wire, hashing or crypto changes:

- Disable unused genawaiter proc-macro and postcard heapless defaults. Arachne
  uses the generator API and std/alloc serialization, not those optional helpers.
- Make standalone tickets optional (still on in upstream default features).
  Arachne uses workspace/recipient-bound grants, not public bearer blob tickets.
  This avoids pulling in another unused heapless/atomic-polyfill dependency.
- Export the existing `gc_run_once` function. Arachne serializes calls so changing
  the single resumable partial reclaims obsolete bytes before another download.
- Bound the file-store runtime to two workers per workspace instead of one per CPU.
- The copied CLI example rejects non-UTF-8 arguments explicitly, rather than
  panicking during argument decoding. It is not included in Arachne binaries.

Remove each change when the corresponding upstream feature/API is available.
`crates/arachne-node/tests/resource_stream.rs` checks >100 MiB streaming, verified
resume, recipient/hash/length authorization, revocation and external-file safety.
These checks qualify our narrow usage, not every upstream feature. Upstream's
0.103 README still cautions that this major API is not production quality;
tablet, release security and pre-TPP gates remain required.
