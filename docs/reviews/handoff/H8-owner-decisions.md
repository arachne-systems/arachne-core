> Written by Claude (AI). Handoff brief H8.

# H8: Owner decisions and outward actions

## BLUF

These actions reach outside this machine or change release state. An agent must not do them
without the owner's explicit approval.

## Waiting on the owner

| # | Action | Why it matters | Notes |
| --- | --- | --- | --- |
| 1 | Push core branches (`integrate/wave1`, `review/core-architecture`) | SDK CI cannot fetch the local-only core pin `2205887` | Choose the GitHub account (owner has several) |
| 2 | Push SDK branches (`fix/b10-b11-locks-pin`, `feat/uniffi-sdk`) | Needed for CI and review | Coordinate with Kotlin PR #1 (another agent) |
| 3 | Publish to crates.io (A9e) | Renamed forks must be published before dependents: `arachne-bao-tree` by hand first, then `arachne-iroh-blobs`, `arachne-iroh-gossip`, `arachne-iroh-tor-transport`, `arachne-node`, `arachne-runtime` | Old `arachne-iroh-blobs 0.103.0` and `arachne-iroh-gossip 0.101.0` sort above the new `-arachne.1` versions; decide whether to yank them |
| 4 | Upstream PR for the Go generator bug | `uniffi-bindgen-go` sends enums with explicit discriminants by position | Patch at `docs/reviews/patches/uniffi-bindgen-go-enum-discr.patch`; public GitHub activity |
| 5 | ATAK host JNA check | Needs the owner's tablet rig | Reset the rig before each run |

## Decisions already made (for reference)

- No legacy workspace or invitation mode; no compatibility code for pre-release formats.
- A2: deterministic tie-break fork choice; removals win.
- A1: UniFFI generates all four languages; the export layer lives in the SDK crate; core provides FFI-friendly types (H4).
- Default limits: 64 sessions, 320 overlay paths per context (ATAK can set lower).
- `close()` waits at most `close_drain` (5 s default, all profiles).
- JNA is a POM dependency of the AAR, not bundled.
- B7d: accepted as proven unreachable, with a guard test.
- Tor: `torut` replaced by a small vendored control client (SAFECOOKIE); the full node test over Tor did not run here (no Tor network reach).
