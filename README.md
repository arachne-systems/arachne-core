# Arachne Core

## BLUF

Arachne Core is the portable Rust foundation for secure peer-to-peer workspaces.
Applications consume the Arachne SDK; the SDK consumes Core's typed contract.
Core owns membership, transport and durable state transitions. Applications own
UI, payload meaning and decisions about delivery to their users.

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
| `arachne-api` | Versioned IDs, errors, events and shared contract types |
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

Open a `Client` in an owned `Context`, with a storage configuration and a
protected storage root key. Core saves each opaque candidate, reads it back,
and then adopts it. Applications protect the keys and storage directory and
acknowledge received content through the durable inbox API.

API version 6 supplies typed errors, events, deadlines and suspend/resume.
Core owns the UniFFI metadata. The SDK generates and packages Kotlin, Swift,
Python and Go bindings from those types. Rust hosts can use the same `Client`
directly. See the [integration guide](docs/integration.md).

## Status

Pre-release software under active development. APIs and persisted formats may
change. Existing installations need an authenticated state upgrade before they
adopt a new stored format. The [work tracker](docs/reviews/2026-09-24-work-tracker.md)
records implementation evidence and open release decisions.

Direct, local and selected relay paths have Rust test coverage. Deployment
qualification must measure the networks and capacities that the application uses.

## Build and test

Install Rust 1.98.0, then run from the repository root:

```sh
cargo +1.98.0 check --locked --workspace
cargo +1.98.0 test --locked --workspace
```

Use the default test thread count. Runtime tests own their sessions through
a `Context`; LAN discovery tests protect their shared fixture locally.
Dependencies use optimization level 2 in development and test builds. Workspace
crates stay unoptimized. See the [development guide](docs/development.md) for
measurements and settings that keep build caches small. These commands build
the portable Rust workspace; they do not require Android, ATAK, or a device.

## Documentation

See the [documentation index](docs/README.md) for the architecture, integration
contract, and security boundaries.

## License

Arachne-authored source in this repository is licensed under the [Mozilla Public
License 2.0](LICENSE). Vendored components retain their own terms; see the
[third-party notices](THIRD_PARTY_NOTICES.md) and [licensing boundary](LICENSING.md).
This license does not grant rights to ATAK, the TAK SDK, or Arachne trademarks.
