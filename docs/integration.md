# Integrating Arachne Core

This repository is a pre-release Rust workspace, not a published SDK. Its
crates are `publish = false`; APIs, wire formats, and saved state can change.
The current typed entry point is `arachne_runtime::Client`. It is synchronous
and owns a Tokio runtime internally, so call it from a blocking worker rather
than from inside an application's async executor or UI thread.

For a small runnable example, see
[`typed_pubsub.rs`](../crates/arachne-runtime/examples/typed_pubsub.rs). It
demonstrates two local clients, explicit routing policy, topic interest, and
opaque byte publication. It does **not** create an MLS workspace or demonstrate
protected group messaging.

## Client startup and identity

`Client::open` takes a `ClientConfig` with a `Network` profile and optional
32-byte endpoint secret. The secret is an endpoint credential; it is not an
MLS workspace key or a human identity. Supply a securely persisted secret when
the host needs a stable endpoint identity across restarts. Protect it as a
secret. The `Direct` profile permits an omitted secret for ephemeral use; the
other typed profiles require one.

| `Network` | Current intent | Important limit |
| --- | --- | --- |
| `Direct` | Direct endpoint connection with no discovery preset. | The host may need to provide address hints. |
| `Lan` | LAN discovery and direct paths. | Does not imply internet-wide lookup. |
| `Nearby` | Nearby/local discovery behavior. | Deployment and platform discovery conditions apply. |
| `Wan` | Public lookup and relay-assisted connectivity. | Does not guarantee a usable route. |
| `RelayOnly` | Prefer relay-only transport behavior. | A custom operator relay is not configurable through `ClientConfig` today. |
| `WanOnly` | WAN lookup without LAN discovery or saved address hints. | Intended for diagnostics; direct paths remain enabled. |

The lower-level node/runtime surface has additional relay configuration. The
typed `ClientConfig` does not currently expose it as an adopter-ready option.

## Workspace lifecycle

The typed API exposes workspace creation, join/admission staging, adoption,
invitations, rosters, and management operations. A typical join path has these
conceptual steps:

1. The joining client calls `begin_join` with invitation material and a display
   name.
2. The workspace owner validates the request with `stage_admission`.
3. The owner durably commits the returned snapshot, then calls
   `adopt_admission`; it can then obtain the retained welcome/commit reply.
4. The joining client calls `stage_join`, durably commits that candidate, then
   calls `adopt_join`.
5. Both adapters refresh routing policy from the accepted workspace state.

The stage/adopt boundary is intentional. Do not emit network effects or advance
the live state before the matching candidate is durably committed. Treat an
uncertain storage result as a recovery case: restore the last accepted
snapshot/state, rather than blindly replaying a cryptographic operation.

### Persistence contract

The host owns storage location, key custody, atomicity, and restore policy. The
typed `stage_*` methods return candidate snapshot bytes; the host must save the
exact bytes durably before calling the corresponding `adopt_*` method. Preserve
the candidate bytes as opaque data and bind them to the workspace and operation
that produced them.

`arachne-store` provides encrypted transactional records. The runtime also has
lower-level native record-storage functions for enabling, saving, and restoring
runtime state. Neither path removes the host's obligation to protect its root
key and storage directory. See [Security](security.md#local-persistence).

`Client::create_workspace` currently creates in-session state and reports
`durable: false`. The typed `Client` does not expose the complete native
record-storage setup/restore lifecycle or a durable initial workspace-creation
operation. Do not treat the typed facade alone as a production-ready persistent
workspace integration.

## Routing and permissions

`install_policy` installs explicit endpoint/topic permissions associated with a
workspace and caller-supplied policy revision. `install_workspace_policy`
derives an all-current-members, all-topics policy from the current MLS roster;
it is a convenience policy, not a least-privilege policy. An adapter should
only install policy derived from accepted, current workspace state.

`set_interest` separately asks to receive a topic. Interest does not grant
permission, and permission does not automatically mean the application wants
to display or persist that topic. Topics are routing labels, not separate MLS
groups; use a separate cryptographic workspace where distinct confidentiality
boundaries are required.

## Publication paths

There are two paths that must not be conflated:

| Path | API | Security meaning |
| --- | --- | --- |
| Basic transport/pub-sub example | `publish` and `poll` | Uses installed routing policy and Iroh transport. It does not encrypt the payload as an MLS group message. The example has no admitted workspace. |
| Protected workspace publication | `stage_protected_publication`, durable save, then `adopt_protected_publication` | Stages an MLS-protected publication and delays network effects until adoption. Persist the exact candidate first. |

`publish` is rejected for a workspace after admission; the runtime directs the
caller to the protected path. Do not use the basic example as a secure group
messaging recipe. The typed facade currently lacks a corresponding protected
receive/stage/adopt method set even though lower-level runtime operations and
tests exercise protected receive. That gap is tracked below.

## Recovery and delivery expectations

The runtime exposes recovery requests, recovery range status, staged recovery,
adoption, and recovered-publication polling. Recovery is peer-assisted and
bounded; it is not a central durable queue. A successful send/admission report
does not mean every offline peer has received the data. Applications must
define their own retention, retry, acknowledgement, and user-visible delivery
semantics around the core's reports and recovery results.

## Known integration gaps

Before presenting this as a supported application SDK, close or explicitly
accept these gaps:

- The typed facade does not yet expose the complete native record-storage
  enable/restore/save lifecycle.
- The typed facade does not yet expose the protected inbound receive and
  durable adoption path that the lower-level runtime API uses.
- `ClientConfig` does not expose custom relay settings available in lower-level
  transport construction.
- Synchronous methods need a documented host threading and cancellation model
  for each target runtime, especially Android.
- The public API has not been declared stable and the crates are not published.

These are concrete implementation boundaries, not guarantees about the timing
of future releases. Check the current API and tests before integrating.
