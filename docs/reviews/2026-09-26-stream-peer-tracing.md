# Peer trace for the Android stream stall

BLUF: Existing transport events now pair each peer, publication sequence,
connection selection, and publisher incarnation. This diagnostic changes no
public API or connection-selection rule.

The `data_fabric_transport` target emits these fields:

- `PTT_MOQ_PACKET_ENQUEUED`: destination peer, workspace, revision, sequence,
  and the local publishing origin hop. This is still a local queue receipt.
- `PTT_MOQ_SESSION_SELECTED`: peer, stable connection ID, dial direction,
  and protocol version.
- `PTT_MOQ_SESSION_REPLACED`: peer and both old and selected connection IDs.
- `PTT_MOQ_SESSION_ESTABLISHED`: peer, stable connection ID, and the first
  announced publisher hop when it is nonzero.
- `PTT_MOQ_PACKET_RECEIVED`: peer, stable connection ID, publisher hop,
  and received sequence after validation and admission.
- `PTT_MOQ_SESSION_CLOSED`: peer, stable connection ID, and error.

A stable connection ID is local to its process. The hop identifies a publishing
origin incarnation, not a member or an authorization grant. Existing endpoint,
workspace, revision, and topic checks still control access.

The hop lookup polls the already announced route once, after the existing
successful subscribe. It uses now_or_never; there is no new wait, deadline,
retry, or readiness gate. Missing and zero first hops remain unknown.

The parent adds a debuggable-APK-only JNI tracing subscriber to Android liblog,
restricted to this target. Core adds no log sink or mobile dependency.

## Evidence

The focused MoQ binaries compile with no incremental data or debug information.
Transport checks use the existing MoQ integration cases, repeated restart
qualification, and a forced duplicate session from the same live publishing
origin. Results are in `/tmp/moq-peer-trace-{stream,handoff,restart}-green.log`.
The deterministic handoff also passed 21 runs before this instrumentation.
These are local checks. The Android receive stall remains open until paired
peer traces identify the cause.
