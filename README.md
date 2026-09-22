# Arachne Core

**The portable Rust foundation for Arachne’s secure, peer-to-peer workspaces.**

Arachne Core provides the shared membership, security, connectivity, and data-
delivery layer used by Arachne applications. It lets admitted participants
form secure workspaces and exchange application data without a central Arachne
application server or TAK Server.

Peers communicate over Iroh. Direct paths are used when available; relay-
assisted paths can help peers connect across restrictive networks. The core
does not require a central service to hold workspace authority or application
payloads. Applications choose what data to exchange; the core treats those
payloads as opaque bytes.

## What it provides

- MLS-based workspace membership, invitations, and administration.
- Authenticated peer connectivity and relay-assisted transport.
- Workspace- and topic-scoped publication and delivery.
- Encrypted local records for workspace state.
- A typed Rust client API for application integration.

## Workspace crates

| Crate | Responsibility |
| --- | --- |
| `arachne-runtime` | Typed application-facing lifecycle and workspace API |
| `arachne-security` | MLS workspace state, membership, invitations, and profiles |
| `arachne-node` | Authenticated peer connections and resource transfer |
| `arachne-routing` | Workspace and topic routing policy |
| `arachne-delivery` | Publication state, delivery, and recovery |
| `arachne-store` | Encrypted local records and freshness checks |

## Integration boundary

Arachne Core is a library, not an end-user application. The ATAK plugin and its
Android/JNI adapter are maintained separately. This repository does not contain
the ATAK host, the TAK SDK, Android UI, a relay service, or ATAK-specific data
translation such as CoT/PLI. Build the plugin only with an authorized TAK SDK
obtained separately.

Applications own their local storage and must follow the client API’s save,
read-back, and adopt steps when accepting state changes. The core does not
silently persist application state on the host’s behalf.

## Status

Pre-release software under active development. APIs and persisted formats may
change; the crates are not published to crates.io. Direct, local, and selected
relay paths have Rust test coverage, but that is not a guarantee of reachability
or capacity on every network or deployment.

## Build and test

Install Rust 1.98.0, then run from the repository root:

```sh
cargo +1.98.0 check --locked --workspace
cargo +1.98.0 test --locked --workspace -- --test-threads=1
```

Tests run serially because some runtime tests share a process-wide session-
capacity limit. These commands build the portable Rust workspace; they do not
require Android, ATAK, or a device.

## Documentation

See the [documentation index](docs/README.md) for the architecture, integration
contract, and security boundaries.

## License

Arachne-authored source in this repository is licensed under the [Mozilla Public
License 2.0](LICENSE). Vendored components retain their own terms; see the
[third-party notices](THIRD_PARTY_NOTICES.md) and [licensing boundary](LICENSING.md).
This license does not grant rights to ATAK, the TAK SDK, or Arachne trademarks.
