# Repository constraints and authorized references

Read the current task in [STATUS.md](../STATUS.md) first. This page preserves detailed repository constraints; it does not assign work. Paths below are relative to the repository root unless absolute.

- This began as a fresh investigation. On 2026-09-08 the user explicitly authorized comparison with TAK Weave: /home/user/development/active/weave-fabric and weave-atak-plugin. Read-only inspection and targeted prior-context lookup for those projects are allowed. Other prior projects/attempts remain excluded; references from Weave do not authorize inspecting them. Record comparison findings here; do not alter or adopt the prior repos implicitly.
- Read DESIGN.md and STATUS.md first; then README.md and linked research only as needed. Update STATUS.md after meaningful implementation/verification changes so compaction does not lose progress.
- Read CONTEXT.md and docs/domain-model.md before extending public domain interfaces. Keep all project findings, decisions, open questions and restart knowledge in this repository. External skills are guidance only; caches and conversation history are not authoritative project records. Architecture/domain guides must stand alone and explain the system without development history or audit narratives; put chronological findings in STATUS.md and evidence/research records. Keep docs/README.md navigation current.
- Scope updated by explicit user goal: implement the first working reusable fabric/plugin and validate between ATAK emulators. Local builds, experiments and emulator setup are authorized. The user authorized the private GitHub repository, release issues and code push on 2026-09-09. Public publication and external infrastructure deployment remain unauthorized.
- The user authorized local upstream copies at /home/user/development/tak/tak.gov/atak-civ-client and /home/user/development/tak/tak.gov/takserver. This does not authorize inspecting sibling projects or prior attempts. Prefer pinned Git objects to modified working files.
- ATAK plugin is the user’s leading integration candidate, subject to evidence.
- The fabric must accommodate future non-ATAK payloads. Keep transport, membership, and storage semantics separate from CoT and ATAK object shapes.
- Primary evidence: public ATAK and TAK Server source, standards, official platform documentation, and explicitly recorded experiments.
- Pin upstream source revisions. Label fact, inference, candidate, assumption, and decision. Source inspection is not runtime validation.
- Preserve broad TAK feature coverage; chat, PLI, and points are examples, not the entire scope.
- No mandatory central TAK Server. Do not quietly substitute a mandatory central broker, identity provider, directory, relay, or ordering service.
- The helper-node policy remains a user decision. A pending question is not approval.
- User prioritizes a practical usable vertical slice and proper seams because fielding will change the architecture. Do not interpret minimalism as authorization to couple ATAK types, transport internals, group cryptography and persistence.
- TAKWerx public examples (https://github.com/takwerx) are user-authorized plugin references. Do not mistake upstream example claims for locally validated behavior.
- User explicitly requires first-class pub/sub fabric behavior. Publish/subscribe, workspace-scoped topics, authorization and declared delivery semantics belong in the fabric, not a CoT-only tunnel.
- User provided /mnt/c/Users/User/Downloads/ATAK-CIV-5.8.0.4-SDK.zip as the SDK baseline; inspect it without copying SDK contents into version control.
- Multiple admins and offline members/admins are required. The earlier designated-admin simplification is rejected; do not restore it or treat silence as authorization. No partition-finality or quorum policy is selected yet.
- Workspace membership privacy is required: do not expose other memberships or reuse a public device/member/transport identifier across workspaces. Use workspace-scoped credentials and adapter identifiers; explain residual IP, callsign and payload correlation honestly. The single saved development-fixture endpoint is not the product's multi-workspace identity model.
- Non-ATAK devices/services (ADSB/AIS feeds or other publishers/subscribers) are first-class fabric clients. Scope permissions separately from human administration and avoid requiring CoT or Android types in the fabric.
- User prefers Kotlin for the ATAK plugin and Rust for portable final-product logic where useful. Temporary implementations may sit behind proper seams; avoid authoring a Java fabric. Kotlin preference does not itself select Compose.
- User requires durable knowledge: assume decisions, plans, roadmap changes, failures and evidence are lost unless written in this repo. Record them as they occur, not only at the end of a session.
- User explicitly requests local git initialization and ongoing commits. Commit coherent progress frequently; never commit SDKs, credentials, build caches or unsupported completion claims. Push to private joshuafuller/arachne is authorized; do not publish private history to the future public repository.
- Fail fast: define observable exit/rejection criteria before an integration choice. Exercise risky assumptions early; report semantic failure versus setup failure accurately. Replace or fix a failed approach before building dependent layers.

- Capture actual emulator screenshots at meaningful visible milestones, including failures. Use scripts/capture-screen.py and maintain evidence/screenshots/README.md with captions and evidence limits. Screenshots must be unedited captures, not mockups or substitutes for routing/security checks.

- The user selected live ADS-B as an integrated demo source: advertise a feed inside a workspace and let users discover and subscribe to it. Keep the reusable fabric and synthetic load fixtures payload-independent; aircraft/vessel schemas belong in adapters. Require measured harness results before scale claims.

- For native visual judgments, inspect original-resolution PNGs. If a preview
  appears to omit content, verify the claimed region against decoded pixels
  before assigning a product defect. Preserve original screenshots and record
  corrections to earlier interpretations; UI-tree text alone remains insufficient.

- On 2026-09-10 local the user explicitly reaffirmed the ATAK client source and
  other TAK material under `/home/user/development/tak/tak.gov` as references,
  beyond the SDK. Use relevant upstream/native examples for issue-owned work;
  this does not start new features or authorize modifying sibling projects.
  Pin the inspected revision and verify target-runtime behavior. All work,
  including UX reviews, documentation and discovered failures, needs a GitHub
  issue owner before implementation; use existing owners where they fit.
