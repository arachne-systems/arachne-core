# Typed publication audience and delivery mode

## BLUF

The Core typed client now exposes the audience and delivery modes that the
native publication operation already supports. The SDK can generate this
contract from Core. The application can send directed or Bulk payloads without
a second SDK schema. Core contains no application payload types.

This package starts at H7 source `70b8c753c311e2f905228ae7d19ce43b66c79131`.
The branch is `codex/night-typed-publication`.

## Contract

`Client::stage_protected_publication_with_options` takes the same workspace,
revision, topic, record ID and payload as the existing method. Its last
argument is `PublicationOptions`:

```rust
struct PublicationOptions {
    recipients: Vec<MemberId>,
    mode: PublicationMode,
}

enum PublicationMode {
    Critical,
    Bulk,
    Current { metadata: PublicationCurrent },
}
```

`PublicationOptions::default()` and the exported
`default_publication_options()` use an empty audience and Critical mode.
Generated language bindings use the exported helper for native defaults.
The enum permits one mode at a time, so Bulk and Current cannot conflict.

An empty audience uses the workspace audience. An explicit audience contains
at most 64 current member IDs in ascending byte order, without duplicates or
the sender. The native operation rejects an explicit audience with Current
metadata. The facade does not sort, deduplicate or relax these checks.
Malformed ID length returns `InvalidId` during ID construction. An unknown
member returns `NotMember`. The other tested audience errors return
`InvalidInput` before the client holds a candidate.

The existing plain method delegates with the native defaults. The existing
`_with_current` method still maps `None` to Critical and `Some(metadata)` to
Current, each with an empty audience. All three methods call
`ops::publication::stage`. Adoption retains native save and read-back before
network delivery. The internal operation and wire format did not change.

## Evidence

The tests were written before the production API. The first build failed with
five missing API errors: `PublicationOptions`, `PublicationMode` and
`stage_protected_publication_with_options` did not exist. Receipt:
`/tmp/h1-publication-api-red.log`.

The scheduler unit test reads the staged native transition and checks all
three delivery classes. It passed. This checks that Bulk reaches the Bulk
queue, which receipt of the payload alone cannot prove.

The new typed integration binary has three tests:

1. Critical and Bulk reach the selected member. A subscribed bystander has no
   directed object. A later group control reaches both peers.
2. Malformed, unknown, self, duplicate, unsorted and oversized audiences fail.
   Directed Current fails. A valid two-member Bulk publication then reaches
   both peers, which proves the errors leave the session usable.
3. The native default helper, existing methods and new Current option retain
   group delivery and the exact Current metadata.

All three tests passed in 10 consecutive runs, with three test threads.
Receipts: `/tmp/h1-publication-options-isolated/receipt.json` and its logs.
The runtime all-target, all-feature Clippy check passed with `-D warnings`,
including the UniFFI metadata derives and exported default helper. Receipt:
`/tmp/h1-publication-clippy-final.log`.

The existing default-feature typed regression binaries passed: `typed_client`
(12 tests), `h4_typed_flows` (2), and `h4_shapes` (1). Receipts:
`/tmp/h1-publication-regressions/receipt.json` and its logs. The internal-error
source ratchet passed. Workspace formatting and `git diff --check` passed.
The new tests run on CPUs 0-3. Cargo used the shared build lock, four jobs,
no incremental cache, and no debug symbols.

The first rejection fixture expected `InvalidInput` for an unknown member.
The existing native code returns `NotMember`. The test now checks that exact
code; the production validator did not change.

## Limits and follow-up

Each test group owns a separate Context and uses three local Iroh endpoints.
An earlier concurrent fixture used the shared default Context. Its valid
Bulk report admitted one peer and failed another with
`transport: Connection was rejected locally`. Receipt:
`/tmp/h1-publication-options-diagnostic.log`. The focused test passed alone.
The final owned-Context tests preserve the audience and delivery assertions.
This package does not claim to fix the shared-context connection rejection.

The lead will merge this package. H5 will then regenerate and test the SDK
bindings. This package does not select an SDK line, change an application or
ATAK dependency, or provide a device receipt.
