# Arachne dependency feature selection

Upstream: bao-tree 0.16.1, crates.io archive SHA-256
`149a2a6017771141e2cd5d0c55b3892d8ff1958df5c318b2e496bf3544b426ed`.
MIT/Apache-2.0 licenses and published source are retained. The root lockfile is
authoritative; package-local lockfiles/registry bookkeeping are omitted.
Trailing whitespace in the upstream README is normalized.

Only the normalized Cargo manifest changes: genawaiter default features are
disabled. Bao's generator API does not use the optional procedural macros that
would pull in the unmaintained proc-macro-error package. No decoder, verifier,
tree, I/O or cryptographic code changes. Remove when upstream selects this feature
set. The real >100 MiB verified transfer/resume check is in arachne-node.
