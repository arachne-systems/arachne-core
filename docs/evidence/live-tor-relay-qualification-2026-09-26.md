# Live Tor and relay qualification

BLUF: a real Tor 0.4.9.11 daemon accepted Arachne's control protocol, endpoint
key and ephemeral onion service, but two Arachne nodes did not exchange data in
a bounded 45-second run. Tor had reached only 45% bootstrap and had no usable
microdescriptors. A real local Iroh relay carried the baseline workspace flow
and four observed relay paths; shutting that relay down produced one explicit,
bounded transport failure and no reconnect claim. Tor production claims remain
blocked.

## Pinned inputs and topology

| Item | Value |
| --- | --- |
| Core commit | `005bc6f183a012f20d434d7888561ed49da4628e` |
| Rust | `rustc 1.93.0 (254b59607 2026-01-19)` |
| Tor image | `arachne-tor-test-proxy@sha256:43e3fdd9f7c2d78205e5384eb8be7f3e9bf81d23b6d8f1f72df4b75d0e38e16f` |
| Tor | `0.4.9.11`, copied from the pinned image and run as the current WSL user |
| Tor listeners | SOCKS5 `127.0.0.1:9050`; unauthenticated test-only control port `127.0.0.1:9051` |
| Iroh relay | `iroh::test_utils::run_relay_server`, local TLS with the harness's test CA bypass |
| Qualification seed | `2730557440` |

The final Tor topology ran the image's Tor binary directly in WSL so Tor and
Core shared one loopback namespace. A prior Docker port-published attempt was
discarded: `ADD_ONION` would have directed container Tor to a container-local
listener while Core listened on the WSL host. Docker host networking also
referred to Docker Desktop's VM, not the WSL host. Neither attempt contributes
to the counts below.

The copied binary dynamically linked against the WSL host libraries. Its own
version output reported Tor 0.4.9.11, Libevent 2.1.12, OpenSSL 3.0.13 and glibc
2.39. This is live daemon evidence for that runtime composition, not a claim
about the container's original library set.

## Commands and results

Every Cargo invocation used the shared build lock and four jobs.

| Scope | Command | Result |
| --- | --- | --- |
| Live Tor control compatibility | `cargo test -p arachne-iroh-tor-transport --lib live_tor_accepts_key_and_reports_same_service_id -- --ignored --nocapture` | PASS: 1 passed in 0.00 s; Tor selected NULL auth and returned the expected service ID. |
| Typed Tor client | `cargo test -p arachne-runtime --features tor --test tor_client -- --ignored --nocapture` | PASS: 1 passed in 0.01 s; a stable supplied endpoint secret produced the expected endpoint key. |
| Tor pub/sub | `timeout 45s cargo test -p arachne-node --features tor --test tor_transport -- --ignored --nocapture` | FAIL: the built test entered its one live case, exchanged no message and was terminated at the 45-second bound (`timeout` exit 124). |
| Live relay baseline | `cargo run -p arachne-runtime --features test-fixtures --example real-iroh-qualification -- --profile relay --relay-infrastructure local --scenario baseline --endpoints 2 --deadline-seconds 120 --receipt /tmp/arachne-live-relay-baseline.json` | PASS in 5,598 ms: 3 real endpoints, 2 complete joins, 4 paths and every path classified `relay`. |
| Live relay loss | `cargo run -p arachne-runtime --features test-fixtures --example real-iroh-qualification -- --profile relay --relay-infrastructure local --scenario relay-loss --endpoints 1 --relay-loss-after-ms 3000 --deadline-seconds 120 --receipt /tmp/arachne-live-relay-loss.json` | PASS in 32,737 ms: 2 real endpoints, 2 relay paths, 1 observed explicit failure, 0 reconnects. |
| Tor parser and framing complement | `cargo test -p arachne-iroh-tor-transport --lib` | PASS: 26 passed, 0 failed, 1 live test ignored. Includes malformed, oversized and EOF control replies, malformed SAFECOOKIE challenges, bounded sender cache and local stream reuse. |
| Stalled peer complement | `cargo test -p arachne-node --test connection_reuse stalled_frame_times_out_without_closing_other_exchanges -- --exact --nocapture` | PASS: 1 passed in 5.01 s; the stalled frame timed out without closing an independent exchange. |

The committed relay receipts are
[`live-relay-baseline-2026-09-26.json`](live-relay-baseline-2026-09-26.json)
and [`live-relay-loss-2026-09-26.json`](live-relay-loss-2026-09-26.json).
Their SHA-256 values are
`f585e8a1e9e1b37b3e4331f07109ac3aa9022b2bdb548cc7818e43d0fc6f7f91`
and `2f97f929290f5b930fd4037ecc84ba5a5fa80a1a4d55c85dc47c6e978efcfa4b`.

## Tor failure observation

The user-level daemon progressed from 5% to 45% during the bounded run:

```text
Bootstrapped 45% (requesting_descriptors): Asking for relay descriptors
We need more microdescriptors: we have 0/9424, and can only build 0% of likely paths.
```

This environment therefore did not establish a public Tor circuit. The
successful control tests prove local control/authentication, deterministic
key conversion and onion-service creation. They do not prove reachability,
payload delivery, reconnect, traffic-analysis resistance, or behavior under a
malicious Tor relay. The 45-second pub/sub timeout is an environment or Tor
reachability failure; it does not isolate a Core defect.

The operator confirmed that the home LAN filters plain Tor while obfs4 works.
This qualification intentionally stops here: Arachne's current Tor profile has
no pluggable-transport configuration surface, so an obfs4 run would test an
external bootstrap path that Core cannot select or reproduce today.

## Metadata observed

- The Tor daemon observed local control connections, onion-service creation,
  bootstrap timing and attempted public relay addresses. With a working
  circuit, the Tor client and guard can observe this host's Tor participation,
  timing and byte volume. The onion service maps deterministically to the
  stable endpoint key by design.
- The local Iroh relay observed endpoint connections, timing and traffic
  volume. The Arachne receipt recorded 42,230 bytes sent and 38,262 received in
  the baseline, and 19,555 sent and 18,608 received before relay loss.
- The relay receipts deliberately omit endpoint IDs, workspace IDs, socket
  addresses, invitations and payloads. A relay route grants no membership or
  application authority.

## Residual risks and release gates

1. Re-run the two-node Tor pub/sub test where Tor reaches 100% bootstrap. A
   successful run is required before claiming Tor data-plane support.
2. Exercise malformed and slow peers through a working public or isolated Tor
   network. The passing parser and localhost checks are complementary evidence,
   not live Tor adversarial evidence.
3. The relay-loss harness shuts the relay down and proves a bounded explicit
   failure. It does not restart the same relay or prove automatic reconnect;
   the receipt correctly reports `reconnected: 0`.
4. Repeat relay loss/restart and Tor recovery across separate hosts and an
   impaired network. This run is single-host evidence and exposes route
   metadata, not WAN behavior.
