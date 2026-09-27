# MLS, Iroh, gossip, and Tor integration security review

Status: internal source review at Core `005bc6f`. This is a reviewer package,
not an independent cryptographic audit or a production approval.

## Review boundary

This review follows data from an authenticated Iroh connection through the
workspace gossip overlay and into OpenMLS, including the optional Tor custom
transport. It checks the assumptions Arachne adds around those libraries. It
does not re-evaluate the security proofs of MLS, Ed25519, QUIC, TLS, Tor, or
the primitives supplied by OpenMLS.

Pinned components at this commit:

| Component | Pinned version | Local source or record |
| --- | --- | --- |
| OpenMLS | `0.9.0` | `Cargo.lock`, `crates/arachne-security` |
| OpenMLS traits/basic credential/Rust crypto | `0.6.0` | `Cargo.lock` |
| Iroh | `1.2.0`, locally patched | `vendor/iroh`, `vendor/iroh/ARACHNE-PATCH.md` |
| iroh-gossip | `0.101.0-arachne.1`, locally patched | `vendor/iroh-gossip`, `vendor/iroh-gossip/ARACHNE-PATCH.md` |
| iroh-tor-transport | `0.1.0-arachne.1`, locally patched | `vendor/iroh-tor-transport`, `vendor/iroh-tor-transport/ARACHNE-PATCH.md` |

Normative and upstream references are [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420),
the [OpenMLS book](https://openmls.tech/book/), and the pinned source above.
The local forks are part of the reviewed implementation; their patch ledgers
identify where behavior differs from the named upstream releases.

## Composition and evidence

The final column names the smallest existing Arachne test that probes the
assumption. A source assertion without a matching test is listed as a finding
instead of being treated as established behavior.

| Assumption Arachne relies on | Implementation and upstream basis | Arachne evidence |
| --- | --- | --- |
| The peer ID returned after an Iroh connection is the Ed25519 endpoint identity authenticated by TLS. | Iroh uses TLS raw public keys and derives `Connection::remote_id` from the peer certificate in `vendor/iroh/src/tls.rs` and `vendor/iroh/src/endpoint/connection.rs`. | `crates/arachne-node/src/endpoint.rs::the_iroh_key_signs_a_binding_every_member_verifies`; connection authorization tests in `connections.rs` and `budget.rs`. |
| Transport authentication alone does not grant workspace membership. | `crates/arachne-node/src/lib.rs::read_gossip_tag` accepts the encrypted workspace tag only when the authenticated remote ID is in the installed policy; data/control paths repeat policy checks. | `overlay.rs::gossip_links_use_one_fixed_alpn_for_every_workspace`, `overlay.rs::removing_a_member_closes_its_gossip_link`, and the outsider case in `gossip_forwarding_test.rs::workspace_publication_crosses_an_intermediate_without_a_direct_route`. |
| An invitation checkpoint identifies one MLS group state rather than any valid signed GroupInfo. | `MembershipVerifier::from_trusted_checkpoint` checks the caller supplied SHA-256 pin, workspace group ID, cipher suite, GroupInfo signature, and ratchet tree in `crates/arachne-security/src/bootstrap.rs`. This follows RFC 9420 GroupInfo and ratchet-tree validation through OpenMLS. | `bootstrap.rs::trusted_checkpoint_rejects_substitution_and_unauthorized_branch`. |
| An MLS BasicCredential cannot substitute an unrelated Iroh endpoint ID. | Each leaf carries a required extension in which the endpoint Ed25519 key signs a domain separated tuple of workspace ID, random member ID, and MLS signature key. `verify_endpoint_binding` validates it for checkpoint and admission leaves. | `bootstrap.rs::a_leaf_without_a_valid_endpoint_binding_is_rejected`; `endpoint.rs::the_iroh_key_signs_a_binding_every_member_verifies`. |
| Admission requires both a valid MLS Add commit and the exact Arachne invitation authorization. | `bootstrap.rs::apply_transition` processes the public MLS commit, requires the administrator committer, exact proposal shape and policy delta, bound joiner leaves, signed invitation, redemption signature, and asserted-time AAD. | `bootstrap.rs::asserted_time_decides_invitation_expiry_for_every_verifier`, `bootstrap.rs::trusted_checkpoint_rejects_substitution_and_unauthorized_branch`, plus the admission cases in that module. |
| Role changes and removals cannot smuggle unrelated MLS or policy changes. | `management.rs` verifies the exact inline proposal, actor authority, target, group-context extensions, and signed revocation order before advancing the public group. | `ordinary_member_cannot_promote_or_remove`, `an_exact_action_does_not_authorize_bulk_role_or_policy_changes`, `exact_removal_and_last_admin_guard`, and `competing_admin_actions_do_not_silently_overwrite_accepted_state`. |
| A self update cannot change the member identity, endpoint binding, capabilities, or group policy. | `bootstrap.rs` accepts a self update only from the same leaf, with empty AAD, no proposals, and an update path whose credential, signature key, capabilities, extensions, and group policy are unchanged. | Self-update rejection cases in `bootstrap.rs`; end-to-end save/adopt coverage in `crates/arachne-security/src/self_update.rs`. |
| Protected MLS application messages are private messages bound to the caller's context and consume receive state once. | `message.rs` rejects public application messages, compares authenticated AAD exactly, extracts the authenticated BasicCredential author, and relies on OpenMLS receive ratchets for replay rejection. The API requires the candidate state to be saved before adoption. | `message.rs::application_authentication_replay_and_restart`, `selective_subscription_requires_bounded_ratchet_recovery`, and `sparse_empty_control_messages_recover_skipped_topics`. |
| Object keys and signatures are bound to workspace epoch, application namespace, author leaf, topic/audience context, and a monotonic counter. | `object.rs` derives an SFrame base with the MLS exporter, derives a namespace key, authenticates the complete publication context, and verifies the current roster author. The host must durably save the incremented counter before release. | `objects_are_independent_authenticated_and_epoch_scoped`, `objects_are_bound_to_their_application_namespace`, `object_namespace_derivation_keeps_its_bytes_across_crypto_upgrades`, and persistence rollback tests. |
| The gossip key conceals workspace overlay discovery but is not an authorization or post-removal confidentiality boundary. | `gossip_key.rs` puts one stable random key only in the Welcome's encrypted GroupInfo extension. `overlay.rs::tag` derives the link preamble from it; the listener separately checks current membership. A removed member retains the old key. | `gossip_key.rs::every_member_shares_one_stable_secret_key`, `a_welcome_without_the_key_fails_closed`, and `overlay.rs::removing_a_member_closes_its_gossip_link`. |
| A relayed gossip payload retains its publisher identity and cannot be rewritten by the forwarding neighbor. | `overlay.rs` signs the compact envelope with the publishing endpoint key and verifies the signature against its claimed sender. The `received_from` transport peer remains separate. | `overlay.rs::a_member_cannot_publish_as_another_member_over_gossip` and `gossip_forwarding_test.rs::workspace_publication_crosses_an_intermediate_without_a_direct_route`. |
| Membership gossip is only a transport hint; MLS verification decides whether it changes state. | `MembershipInbox` queues bounded opaque bytes. The runtime later decodes and applies them through `MembershipVerifier`; reception itself does not install policy or keys. | `overlay.rs::membership_inbox_wakes_and_scopes_queued_payloads`, `a_flooding_member_cannot_crowd_out_another_members_step`, and the security transition tests above. The author-admission gap is finding PI-01. |
| A relay can observe endpoint identifiers, timing, and sizes, but cannot read Iroh QUIC or MLS/object plaintext solely by relaying it. | Iroh authenticates and encrypts the end-to-end QUIC connection in the pinned TLS/endpoint source. MLS and protected objects add application encryption. This is a code-derived trust assumption; it has not had an independent deployment review. | Local direct/relay transport and protected-message tests. Live metadata qualification is PI-06. |
| Tor changes the route but Iroh still authenticates the remote endpoint above the custom packet transport. | `TorPreset` removes IP/relay transports and installs only the custom Tor transport; Iroh TLS still runs after packets enter the endpoint. | `vendor/iroh-tor-transport/src/tests/user_transport.rs::test_user_transport_roundtrip_local`. This uses local TCP substitution, so live Tor behavior remains PI-06. |
| Candidate security state becomes visible only after durable save and read-back. | Security APIs return staged candidates. Runtime integration follows stage, save, read-back, adopt ordering documented in `docs/security.md` and `docs/integration.md`. | Restart and replay tests across `arachne-security`, plus runtime membership integration tests. |

## Findings

| ID | Severity | Finding | Tracking and required proof |
| --- | --- | --- | --- |
| PI-01 | High | A current member can relay a self-signed membership envelope whose claimed author is outside the roster. The receiver queues by claimed author before MLS verification, allowing arbitrary endpoint keys to consume the 64-author inbox. This cannot forge an MLS transition, but it can crowd out valid work. | `ptt-60z.4.1`: reject non-member envelope authors before queueing and preserve behind-member forwarding in a regression test. |
| PI-02 | High | Plumtree's received-ID cache, payload cache, missing-message map, expiry heap, and pending lazy push work are time bounded but not count or byte bounded. A malicious member can grow them with unique Gossip/IHave IDs before application queues apply backpressure. | `ptt-60z.4.2`: add deterministic count/byte bounds and adversarial tests in the shared protocol state. |
| PI-03 | Critical | `read_tor_packet` allocates a peer-declared `u32` length before Iroh authentication. A reachable onion peer can request a multi-gigabyte allocation without sending a body. | `ptt-60z.4.3`: reject oversized frames before allocation and test the exact boundary. |
| PI-04 | High | The Tor accept loop spawns an unbounded task for each unauthenticated raw stream and gives framing reads no deadline. Idle or slow peers can exhaust sockets and tasks before Iroh connection budgets apply. | `ptt-60z.4.4`: add a shared inbound limit and read deadline with saturation/recovery tests. |
| PI-05 | High, design review required | The Tor adapter expands the Iroh endpoint secret seed and sends equivalent Ed25519 signing material to the Tor control daemon in `ADD_ONION`. Compromise of that daemon can therefore become compromise of the Iroh endpoint identity, and one key is reused across protocol roles. | `ptt-60z.3.2`: use a separate onion key and an authenticated, replay-resistant endpoint-to-onion mapping; obtain independent cryptographic review. |
| PI-06 | Medium, release evidence | Existing Tor tests replace Tor with local TCP. Relay confidentiality and metadata claims are inferred from code, not exercised against a real Tor daemon/relay with malformed, stalled, reconnecting, or observing peers. | `ptt-60z.7.1`: record bounded live adversarial qualification before production claims. |
| PI-07 | Release blocker | No independent cryptographer has reviewed the Arachne composition, custom endpoint binding, invitation authorization, recovery ordering, exporter use, or proposed Tor key mapping. | `ptt-60z.3`: review the bounded package below and track every response to closure or explicit residual risk. |

## Package for an independent reviewer

Provide one immutable Core commit containing this document and the exact
`Cargo.lock`. The useful review set is deliberately bounded to:

- `crates/arachne-security/src/{lib,bootstrap,management,pending,message,object,gossip_key}.rs`
- `crates/arachne-node/src/{endpoint,connections,budget,overlay,lib}.rs`
- `vendor/iroh/{ARACHNE-PATCH.md,src/tls.rs,src/endpoint/connection.rs}`
- `vendor/iroh-gossip/{ARACHNE-PATCH.md,src/proto/plumtree.rs,src/proto/util.rs}`
- `vendor/iroh-tor-transport/{ARACHNE-PATCH.md,src/lib.rs,src/control.rs,src/onion.rs}`
- `docs/security.md`, `docs/integration.md`, and this review

Ask the reviewer to answer these questions in writing:

1. Does the endpoint-binding extension prevent credential/endpoint
   substitution across workspaces and MLS signature keys?
2. Do admission, management, self-update, and recovery verifiers authorize
   exactly the intended MLS transition, including replay and fork cases?
3. Are exporter labels, namespace derivation, AAD, signatures, counter
   persistence, and recent-epoch receive behavior safely composed?
4. Can an authenticated transport peer or gossip forwarder cause state or
   policy changes without a valid MLS authorization?
5. Does the proposed separate Tor onion key mapping bind endpoint, onion key,
   freshness, and rotation without reintroducing a discovery substitution?
6. Which confidentiality, forward-secrecy, metadata, or availability claims
   should be narrowed?

Run the following at the reviewed commit:

```sh
flock /home/user/development/worktrees/.cargo-build.lock nice -n 10 env CARGO_BUILD_JOBS=4 cargo test -p arachne-security -p arachne-iroh-gossip -p arachne-iroh-tor-transport
flock /home/user/development/worktrees/.cargo-build.lock nice -n 10 env CARGO_BUILD_JOBS=4 cargo test -p arachne-node --lib
```

Acceptance requires a named reviewer, the reviewed commit and dependency pins,
written answers to all six questions, and a Beads item for every new finding.
Until then, this document supports engineering decisions only.
