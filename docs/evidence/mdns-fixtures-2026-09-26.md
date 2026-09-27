# mDNS test isolation

## BLUF

All six mDNS tests pass under Cargo with four test threads. Three consecutive
runs passed. Keep fresh fixture identities and serialize multicast fixtures.
The production lookup behavior is unchanged.

## RED

The full integration suite ran the six upstream tests at once. They all used
ChaCha seed zero. `mdns_publish_resolve` received another test's relay metadata;
`non_advertising_endpoint_not_discovered` found another test's advertised peer
with the same identity. Four tests passed and two failed.

Fresh random identities removed that collision. Concurrent multicast binds
still caused discovery timeouts in each of three runs. The upstream module
name requests nextest isolation, but Cargo does not enforce that request.

## GREEN

One test-only Tokio mutex now enforces the upstream isolation rule for Cargo.
All assertions and timeout limits stay unchanged. The test command is the
built crate's lib-test binary with `--test-threads=4`, on CPUs 28-31.
Three runs each passed six tests in 16.27, 16.32 and 16.28 seconds.
Build: `cargo +1.98.0 test --locked -p arachne-iroh-mdns-address-lookup
--lib --no-run --message-format=json`, under the shared Cargo lock.
