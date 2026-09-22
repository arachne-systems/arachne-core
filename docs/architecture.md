# Architecture and boundaries

Arachne Core is a Rust workspace that composes membership security, peer
connectivity, routing, delivery/recovery, and encrypted local records. It is a
library substrate for host applications; it is not an end-user application or
a server that owns every workspace.

## Terms used in the code

| Term | Meaning in Core | Not the same as |
| --- | --- | --- |
| Endpoint | An Iroh network identity used to address a running node. | A verified person, agency, or device owner. |
| Workspace | An MLS group and its Arachne workspace state. | A server-side room or topic. |
| Member | A credentialed participant in one workspace, associated with an endpoint for routing. | A globally verified account. |
| Epoch | MLS membership generation after a group transition. | The separately supplied routing-policy revision. |
| Topic | An application-defined string used to classify and route publications. | An independently encrypted MLS subgroup. |
| Interest | A member's request to receive a topic. | Permission to publish or membership authorization. |

These distinctions matter: a successful network connection does not admit a
member, workspace membership does not establish real-world identity, and topic
filtering does not create cryptographic isolation between topics.

## Crate map

| Crate | Owns | Does not own |
| --- | --- | --- |
| `arachne-security` | MLS workspace state, credentials, invitations, membership changes, and protected application messages. | Network discovery, ATAK identities, or host persistence policy. |
| `arachne-node` | Iroh endpoint lifecycle, peer connections, network control, and resource transport. | Workspace admission decisions or application payload meaning. |
| `arachne-routing` | Workspace/topic policy, endpoint permissions, and subscription routing decisions. | MLS membership cryptography or user-facing subscription UI. |
| `arachne-delivery` | Publication tracking, bounded retained data, and authorized recovery state. | A durable service-side message queue or guaranteed delivery. |
| `arachne-store` | Encrypted local records, atomic revisions, and optional freshness-anchor comparison. | Key provisioning, directory protection, backups, or host lifecycle. |
| `arachne-runtime` | Composition, session lifecycle, typed Rust client, and lower-level runtime operations. | Android/JNI integration, app UI, or automatic durable storage setup. |

The dependency direction is intentionally layered: `runtime` composes the
other crates; `delivery` coordinates security and routing; `node` uses routing
and Iroh; `store` is a separate local persistence primitive. Keep ATAK-specific
types and Kotlin/JNI adaptation in the ATAK application repository.

## Conceptual message path

```text
Host application
      │ typed Client or lower-level runtime operation
      ▼
Runtime ─────── Store (host-controlled commit/restore)
      │
      ├── Security: MLS membership and protected group messages
      ├── Routing: endpoint/topic policy and subscription interest
      ├── Delivery: bounded publication state and recovery
      └── Node: Iroh discovery, authenticated QUIC paths, resource transfer
                                      │
                                      ▼
                              Peer runtime / host
```

This is a boundary diagram, not a promise that each operation always passes
through every crate. For example, the basic `publish`/`poll` demonstration path
is not MLS-protected; see [Integration](integration.md#publication-paths).

At a high level, a protected publication is staged against current workspace
state, committed by the host, then adopted so Core can advance the local
cryptographic state and perform the resulting network effects. An inbound
protected operation follows the corresponding receive/commit/adopt path. The
exact candidate and recovery surfaces differ between the typed facade and the
lower-level runtime API today.

## Connectivity and decentralization

Peers can connect directly where network conditions allow. Profiles can also
use local discovery, public address lookup, or Iroh relay-assisted paths. These
mechanisms help endpoints find and reach one another; they do not own workspace
membership or application payloads. Arachne Core does not require a central
Arachne application server or TAK Server, but “no application server” does not
mean “no network infrastructure”: discovery and relay services can participate
in connectivity.

Reachability, availability, peer discovery, and delivery timing depend on the
selected profile and deployment. A configured profile is not a guarantee that
every peer can connect through every firewall or network.

## Outside this repository

Core does not contain the ATAK host APK, TAK SDK, Kotlin plugin, Android UI,
signing pipeline, feed directory, operator service, or the official Arachne
relay deployment. It treats application payloads as bytes and does not parse
CoT, PLI, chat, or other domain formats. The host application must adapt its
identity and lifecycle model, provide persistent storage and protected keys,
translate application objects, and choose what data to publish.

## Current release status

All eight workspace crates have an initial release on crates.io. The workspace
remains pre-release: wire formats, saved state, and APIs can change.
The typed `Client` is useful for Rust integration work, but it is not yet a
complete, stable application SDK;
see the specific gaps in [Integration](integration.md#known-integration-gaps).
