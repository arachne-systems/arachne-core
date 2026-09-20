# Portable live pub/sub

`arachne-routing` is a dependency-free library for exact-topic interests and
workspace permission checks. `arachne-node` assembles it with direct authenticated
Iroh QUIC links. Neither depends on ATAK, CoT, Kotlin or Android types.

Internally, `connections.rs` owns Iroh endpoint construction, LAN lookup,
address hints, network-change notification and dialing. `Node` owns verified
routing state and data/control admission. This is a concrete module boundary;
there is no generic transport interface while only one production transport
exists.

The `two_peers` example exercises the same public interface on Linux and Android.
Its policies arrive through a test coordinator's stdin. That is a test fixture,
not invitation verification or a group-management protocol.

## Interface and responsibility

1. `Node::bind(address)` returns a node and a bounded message receiver. This
   entrypoint generates a fresh device identity.
   `Node::bind_with_identity(address, &secret)` accepts a securely generated
   32-byte credential held by the caller's storage implementation. It restores
   transport identity only; policies and subscriptions still start empty. The
   caller must prevent simultaneous endpoints using the same credential.
   `Node::bind_lan(address)` additionally opts into local multicast address lookup
   and advertisement of the endpoint key/IPs under the `data-fabric` service.
   The caller still supplies expected peer keys and verified workspace policy.
   `Node::bind_wan_with_identity(address, &secret)` retains that LAN lookup and
   also enables the pinned Iroh `N0` Pkarr lookup and relay configuration. Those
   helpers supply routes only; they do not discover workspaces or grant access.
2. `install_verified_policy(workspace, revision, endpoint_permissions)` accepts a policy that
   the trusted application has already authenticated and authorized. There is no
   network operation to replace policies. Production integration must provide
   policy verification and durable revision/identity storage first. The map is
   an endpoint permission projection, not a member registry. Member/device
   bindings are the caller's responsibility; revision is not a crypto epoch.
3. `add_address_hint(peer, address)` supplies a dial hint, not a membership grant.
   Connections authenticate the expected peer key independently of that address.
4. `subscribe`/`unsubscribe` update local interest and notify permitted publishers.
   Membership alone does not subscribe. Caller operations for a topic should be
   awaited in order; concurrent/replayed interest reconciliation is unfinished.
5. `publish` checks current publishing permission. When a workspace overlay is
   enabled, it forwards once through bounded Gossip neighbors; receivers still
   check their own policy, revision and interest before emitting an application
   event. Without an overlay, it routes directly to known interested readers.
   A dishonest sender changing its local policy cannot grant itself remote rights.
   `publish_to` additionally takes a nonempty canonical recipient-member scope
   and endpoints already resolved by the security owner. It intersects those
   endpoints with current subscriptions and reports each unannounced subscriber
   as `NotSubscribed`, without widening the audience. The receiver independently
   checks its current permission and local interest before
   admitting it. This is generic recipient-scoped pub/sub, not a chat API.
6. The report distinguishes admitted peers from failures. Admission is acceptance
   by the peer's bounded consumer queue, not application delivery or a read receipt.
   A timeout may occur after admission. There is no automatic retry or deduplication.
   Deadline errors identify the last pending stage (connect, open stream,
   authorization recheck, frame write or acknowledgment read) within the same
   five-second operation budget. The stage is diagnostic evidence, not a receipt.
7. `close` closes the endpoint and cancels the listener and its bounded workers.
   Dropping a node also cancels the listener. Drain already-admitted messages
   explicitly if wanted; revocation/unsubscription does not erase prior plaintext.

## Diagnostics

The `data_fabric_transport` tracing target emits operation stages, public peer
keys, local connection IDs, encoded byte counts, admission outcomes and connection
statistics on failures. It does not log payloads or secret credentials. Consumers
choose their subscriber; the Android binding installs a bounded Android log sink
only in debug builds. These records expose communication metadata and belong in
controlled diagnostics, not a public membership directory. A local connection ID
is process-specific and cannot be matched directly to the remote connection ID.

## Current limits

- Live data only; recipient-scoped publications have no retained catch-up or
  offline queue. No invitations or admin UI live in this module.
- Workspace-wide publications can use one Gossip overlay with at most five
  maintained neighbors. Direct recipient publications stay on their acknowledged
  direct path. The module forwards opaque bytes; protected workspace payloads are
  produced and verified by the security/runtime layer.
- Direct and LAN-only constructors enable no public helper. The internal Android
  runtime now selects the explicit WAN constructor, which uses Iroh's public
  `iroh.link` Pkarr/DNS lookup and default relays as a documented development
  dependency. The build keeps Iroh's optional portmapper feature disabled.
- At most 32 workspaces, 4096 authorized endpoints per workspace, and 64 exact topics
  per permission set. These are input bounds, not measured scale guarantees.
- Topics are case-sensitive ASCII names, up to128 bytes, with nonempty slash
  segments. Wildcards are unsupported.
- Payloads up to16KiB, encoded frames up to128KiB; 256 queued consumer messages.
  Full/closed queues reject publication instead of returning false success.
- At most32 inbound handlers, each bounded to5 seconds. Direct fanout runs up to16 operations concurrently per call and opens a
  connection per operation. Concurrent callers multiply that per-call bound;
  the Android facade serializes its commands. The runtime reserves at most 24
  aggregate Gossip-neighbor paths across its active workspace sessions.
- Policies must increase monotonically in memory. Restart rollback protection,
  partition finality and cryptographic group transitions remain unfinished.
- Traffic already admitted while authorized may remain in flight after a policy
  change. Disconnected uninformed peers cannot instantly enforce revocation.

## Runnable checks

```sh
cargo +1.98.0 test --locked -p arachne-routing -p arachne-node
cargo +1.98.0 build --locked -p arachne-node --example two_peers
python3 scripts/check-pubsub.py --output .cache/pubsub-host.json
scripts/build-peer-android.sh -p arachne-node --example two_peers
python3 scripts/check-pubsub.py --android --output .cache/pubsub-android.json
python3 scripts/check-pubsub.py --lan-lookup --output .cache/pubsub-lan-host.json
python3 scripts/check-pubsub.py --android --lan-lookup --output .cache/pubsub-lan-android.json
python3 scripts/check-wan-relay.py --output .cache/pubsub-wan-relay.json
```

`two_peers --wan-lookup` exchanges only Endpoint IDs through the configured
Pkarr and relay path. `check-wan-relay.py` runs that executable on two isolated
Docker networks and requires both peers to record relay paths.

Android checks use the project's two emulators on their shared virtual Wi-Fi LAN.
They verify the deployed executable hashes, both publishers/subscribers, exact
binary payloads and an unsubscribed workspace. They do not exercise the ATAK
plugin or internet NAT traversal. See repository STATUS.md for current evidence.

## Initial load baseline

```sh
cargo +1.98.0 build --locked --offline -p arachne-node --example load
target/debug/examples/load 12 20 256 > evidence/load-local.json
```

Arguments are total participants (one publisher, remaining subscribers),
publication count and payload bytes. Each participant owns a real Iroh endpoint;
all endpoints run in one process on loopback with explicit policy/address fixtures.
The producer sends as fast as the current serial publication operation permits.
Consumers independently validate source, workspace, topic, sequence and bytes.
The JSON separates queue admission from consumer receipt, counts missing/duplicate
or invalid data and checks an unsubscribed workspace and unsubscribe behavior.
Invalid input, failed setup, the 180-second deadline or delivery-check failure
produce `passed:false` and a nonzero exit. `passed:true` means delivery checks
passed, not that throughput is acceptable. Run smaller counts before increasing.

Latency uses a shared monotonic clock from publication start to consumer receipt,
including serial fanout delay. Payload throughput is not wire bandwidth. The
harness does not measure CPU/memory itself; an external `/usr/bin/time -v` receipt
can measure the whole process, including setup and teardown. These debug-build
measurements are neither a release benchmark nor Android/Internet evidence.
No MLS, secure admission, feed advertisement, live source, reconnect, paced or
multi-publisher traffic is exercised yet. These remain integrated harness gates.

Recorded baseline: 12 participants delivered 220/220 messages with p99 143 ms;
100 delivered 1,980/1,980 with p99 1.60 s and only 0.63 publications/s. Both used
20 publications of 256 bytes. See `evidence/load-baseline-2026-09-08.json` for
artifact/source hashes and links to raw receipts. Do not extrapolate these results
to 1,000 participants; current fanout requires improvement first.

The bounded-concurrency comparison (`evidence/fanout-100-2026-09-08.json`)
retained all1,980 deliveries while raising100-endpoint throughput to8.07
publications/s and reducing p99 to126 ms. This is one matched debug run, not a
capacity guarantee. A regression check keeps the first sorted recipient stalled
while requiring a healthy recipient to receive within2 seconds; the stalled peer
still returns its explicit acknowledgment timeout. Buffering polls borrowed
futures without detached tasks, so cancelling the caller drops pending work.

## Authenticated control requests

`request_control(peer, payload)` uses the same Iroh endpoint identity and supplied
address hints, with separate ALPN `data-fabric/control/1`. `poll_control()` returns
an owned `ControlRequest` containing the connection-authenticated peer and opaque
payload; caller-supplied identities inside bytes do not replace that peer.
`respond(bytes)` consumes the request. Dropping it rejects the request. The host
must validate application authority and perform required durable writes first.
No MLS, group policy or Android types are introduced into the transport module.

Requests are bounded to32KiB and replies128KiB. There are at most8 queued requests and8 active
control handlers inside the existing32-handler total limit. The 30-second control
deadline includes a five-second connect stage and host response time; delayed storage may cause timeout
after a transition committed. The application must use retained-response retries,
not silently repeat the transition. Expired queued requests are dropped on poll.
A successful respond call queues bytes, not a remote application receipt.

The host control identity check and native admission retry use actual loopback
Iroh. Android instrumentation exercises live Iroh admission between two endpoints
inside each emulator with actual AtomicFile save/adopt and joined-state restore.
This is not cross-emulator onboarding, discovery/NAT or full plugin UI evidence.

## Protected pub/sub assembly check

```sh
cargo +1.98.0 run --locked --offline -p arachne-node --example protected -- .cache/protected-pubsub-NEW
```

Use a new directory under the repository. The example assembles the existing
security, routing and transport libraries in a non-ATAK client. Security is a
**dev dependency for the example**, not part of Node's transport implementation.
It creates two independent endpoint roots and a real MLS workspace/admission,
then derives the routing endpoint maps from each side's verified member roster.
Its explicit local default policy permits all admitted members to publish/read
three registered demonstration topics; interests remain selective. Policy
revision17 is deliberately different from MLS epoch1. No general distributed
policy synchronization or fine-grained role model is claimed.

Actual QUIC/TLS links carry binary data and a JSON reply between distinct Iroh
endpoints on loopback. Sender snapshots are atomically written/read back before
publication. Reception authenticates a disposable candidate, saves it, and only
then checks application delivery. Expected routing metadata is bound through
PublicationContext AAD, and the authenticated author's endpoint must equal the
direct transport sender. Forwarded authors require a different hop-authorization
rule; this test does not implement forwarding.

Checks include outsider subscription rejection despite the outsider forging its
own local policy, topic/ID substitution rejection, replay rejection after loading
the receiver snapshot, no recipients after unsubscribe, and a12KiB update after
resubscribe with one skipped sender generation. This is not a throughput/scale,
NAT, Android or live-source measurement. Admission cryptography is performed in
process; data publication/subscription uses real Iroh connections.

The state directory contains encrypted workspace files; endpoint roots remain in
RAM and are intentionally not exported. This is a runnable integration check,
not a deployable service credential store. IDs are deterministic within a fresh
random workspace for reproducibility. Product publishers must allocate fresh
workspace-scoped publication IDs and retain the same packet for retransmission.

## Learning a direct return path

After a received pub/sub frame passes routing authorization and queue admission,
the node may remember the connection's observed direct source address under its
authenticated endpoint ID. The address is not supplied by the payload. Rejected
frames and control requests do not populate this cache. The existing 4096-peer
address bound applies; an existing entry can be refreshed, while a new entry is
skipped when full. Relay/custom incoming addresses are not converted to IP hints.

A joining subscriber that knows a publisher's address can therefore establish a
return path by sending an authorized subscription. The publisher does not need a
manually copied subscriber address. This cache grants no workspace authority and
is neither persistent discovery nor an internet reachability guarantee. At least
one initial reachable hint is still needed; reconnect after both sides restart,
address changes, relay paths and general NAT traversal require separate evidence.

Learning a return path does not synchronize the other peer's subscriptions.
A subscription announcement whose send failed still needs retry. Applications
must distinguish permission, reachability, expressed interest and data delivery;
an empty publication recipient list is not evidence that a remote user received
anything. The two-emulator integration check retries both announcements and
orders its first publication after the intended receiver's interest is known.

## Incoming work budgets

The listener admits at most 512 concurrent handshakes. After transport
authentication it releases that slot and separately admits at most 32 data
handlers or 512 control handlers. Control connections are capped at 512 and
their inbox is capped at 512 requests, so a shared-link onboarding burst can
queue without consuming the data-plane budget. These are bounded transport
resources, not membership limits; the application still validates and batches
admissions before committing them.
An incomplete data stream cannot hold a handshake or control slot for its
remaining lifetime. This does not bound all internal QUIC memory or replace
application-level rate limiting for hostile floods.

`cargo test -p arachne-node --test live_pubsub stalled_data_connections_do_not_consume_control_capacity -- --nocapture`
holds 32 authenticated data connections on incomplete JSON and requires an
independent authenticated control request/reply within two seconds. It closes
all endpoints before evaluating the control result. It tests the transport seam,
not membership authorization or the fairness of chat and feeds sharing data slots.

The explicit 500-client control burst is run with:

`taskset -c 0-3 env ARACHNE_CONTROL_BURST_MEMBERS=500 cargo test --release -p arachne-node --test control_burst authenticated_control_burst_handles_500_clients -- --ignored --nocapture --test-threads=1`

This creates independent authenticated local endpoints and measures the
transport queue, not 500 physical Android devices or a WAN/relay path.
