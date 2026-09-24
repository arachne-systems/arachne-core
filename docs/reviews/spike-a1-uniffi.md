> Written by Claude (AI).

# Spike: UniFFI 0.31 bindings for the `arachne-api` contract (ADR A1/A4, step 7)

Date: 2026-09-24. Branch: `spike/a1-uniffi`. Input: [ADR A1/A4](adr-a1-a4-sdk-contract.md),
decision 1 ("Constraints and risks") and step 7 ("Spike `#[non_exhaustive]` with UniFFI first").

## BLUF

- One Rust surface generates working Kotlin, Swift, Python and Go bindings. All four tests pass.
- `#[non_exhaustive]` compiles on `uniffi::Enum`, `uniffi::Error` and `uniffi::Record` in 0.31.2.
  No workaround is necessary. The foreign enums are exhaustive, so the ADR rule stays: foreign code
  keeps an `else`/`default` branch.
- The error code crosses the boundary intact (101, 103 and 1) in all four languages.
- `close()` from a second thread releases a parked `next_event(30000)` in about 200 ms in all four languages.
- **Go has one real bug.** `uniffi-bindgen-go` v0.7.1 writes wrong wire values for enums with explicit
  discriminants (our `ErrorCode`). The stock generator fails the Go test. A 44-line template patch
  fixes it, and then the Go test passes. We must send this fix upstream or keep the patch.
- Four smaller API-shape findings change the ADR design a little. See "Findings".

## Versions used

| Item | Version | Source |
| --- | --- | --- |
| `uniffi` (scaffolding and `uniffi-bindgen` for Kotlin, Swift, Python) | `=0.31.2` (latest 0.31 patch, 2026-06-17) | crates.io. 0.32.2 is the latest overall (2026-09-23). |
| `uniffi-bindgen-go` | `v0.7.1+v0.31.0` (2026-04-16), latest release | GitHub `NordSecurity/uniffi-bindgen-go` |
| `uniffi_bindgen` inside `uniffi-bindgen-go` | 0.31.2 | Its requirement is `"0.31.0"` (caret). Without `--locked`, cargo picks 0.31.2. |
| Rust | 1.93.0 | |
| Kotlin / JVM / JNA | kotlinc 2.3.0, OpenJDK 21.0.12.1, JNA 5.17.0 | |
| Swift | 6.1.3 (Linux), language mode 6 | |
| Python | 3.14.5 (uv) | |
| Go | 1.23.5 | |

The Kotlin, Swift and Python generator is a `[[bin]] uniffi-bindgen` in the spike crate. It calls
`uniffi::uniffi_bindgen_main()`, so it has the same version as the scaffolding.

## What was built

- `crates/arachne-api`: optional feature `uniffi` (`uniffi = { version = "=0.31.2", optional = true }`).
  With the feature on:
  - `uniffi::setup_scaffolding!()`.
  - `ErrorCode`, `Network`, `Event`, `Feature`: `derive(uniffi::Enum)`.
  - `ApiError`: `derive(uniffi::Error)` (enum with fields). `code()` is exported as a method.
  - `Capabilities`: `derive(uniffi::Record)`.
  - `ErrorCode::number()` is exported. It gives the stable number.
  - `api_error_code(&ApiError) -> ErrorCode` is exported as a free function (see finding 3).
  - ID newtypes: `uniffi::custom_type!` over a lowercase hex `String`, with `try_lift` = `from_hex`.
  - With the feature off, nothing changes. `cargo test -p arachne-api` passes both ways.
    `arachne-runtime` does not pull `uniffi`.
- `crates/arachne-uniffi-spike` (throwaway `cdylib`, `publish = false`): `SpikeClient` object with a
  `Result` constructor, `parse_endpoint`, `describe_peer(EndpointId)`, `capabilities`, `push_event`,
  blocking `next_event(timeout_ms) -> Option<Event>`, `wake()` and `close(&self)`. It uses a `Mutex` and a
  `Condvar`. No lock is held while it waits.
- `crates/arachne-uniffi-spike/tests-foreign/{kotlin,swift,python,go}`: one test for each language.
- `crates/arachne-uniffi-spike/run.sh`: builds, generates the four bindings and runs the four tests.
- `crates/arachne-uniffi-spike/bindgen-go-enum-discr.patch`: the Go generator fix.

Each foreign test does these checks:

1. `parse_endpoint("zz")` throws `ApiError.InvalidId`, and the code number is 101.
2. `describe_peer("not-hex")` fails in the UniFFI lift step and still throws a typed `InvalidId` (101).
3. The constructor with `Network.TOR` throws `ApiError.State`, code 103.
4. A pushed `Event.PRESENCE` comes back. The `#[non_exhaustive]` `Capabilities` record crosses.
5. `wake()` releases a parked `next_event`.
6. `next_event(30000)` is parked on one thread. `close()` is called from another thread. The waiter must
   return `None` within 2 s. (The long timeout makes sure that the test fails if `close()` does not wake it.)
7. After `close()`, a call throws `ApiError.Closed`, code 1.

## Results

| Language | Generated OK | Test passed | Notes |
| --- | --- | --- | --- |
| Kotlin | Yes | Yes | Needs a rename of `close` (finding 1). `ErrorCode` is `enum class ErrorCode(val value: UInt)` with the real numbers. |
| Swift | Yes | Yes | Compiles in Swift 6 language mode. `ErrorCode: UInt32` has the real numbers as `rawValue`. All generated files go into one module. |
| Python | Yes | Yes | Generated modules use relative imports, so they must be in a package. The `code` field hides `code()` (finding 3). |
| Go | Yes | **Stock v0.7.1: no. Patched: yes.** | Enum discriminant bug (finding 2). No methods on error types (finding 3). |

Exact output lines. Command: `run.sh` with the patched Go generator, output in `run-patched.log`, then
`grep -E "^==|^ok: .*(error code|discriminant|returned)|PASS|spike_test.go:(41|49|54|61|72|122|132|133)" run-patched.log`
(an excerpt; the full log has more `ok:` lines):

```text
== kotlin
ok: parseEndpoint error code = 101 (INVALID_ID)
ok: ErrorCode.value discriminant = 101
ok: describePeer lift error code = 101
ok: constructor error code = 103
ok: waiter returned after close()
ok: next_event returned null after 203 ms
ok: after close error code = 1
KOTLIN PASS
== swift
ok: parseEndpoint error code = 101 (invalidId)
ok: ErrorCode.rawValue discriminant = 101
ok: describePeer lift error code = 101
ok: constructor error code = 103
ok: waiter returned after close()
ok: next_event returned nil after 200 ms
ok: after close error code = 1
SWIFT PASS
== python
ok: parse_endpoint error code = 101 (ErrorCode.INVALID_ID)
ok: ErrorCode.value discriminant = 101
ok: describe_peer lift error code = 101
ok: constructor error code = 103
ok: waiter returned after close()
ok: next_event returned None after 200 ms
ok: after close error code = 1
PYTHON PASS
== go
=== RUN   TestSpike
    spike_test.go:41: ok: ParseEndpoint error code = 101
    spike_test.go:49: ok: Go ErrorCode value = 101 == ErrorCodeInvalidId
    spike_test.go:54: ok: Go-made ApiError lowers ErrorCodeUnsupported as 103
    spike_test.go:61: ok: DescribePeer lift error code = 101
    spike_test.go:72: ok: constructor error code = 103 (ApiError: State: Code=103, Detail=tor is not in this build)
    spike_test.go:122: ok: NextEvent returned nil after 200 ms
    spike_test.go:132: ok: after close error code = 1
    spike_test.go:133: GO PASS
--- PASS: TestSpike (0.40s)
PASS
```

Go with the stock v0.7.1 generator:

```text
    spike_test.go:41: ok: ParseEndpoint error code = 101
    spike_test.go:47: Go ErrorCode value = 5, want 101 (ErrorCodeInvalidId)
--- FAIL: TestSpike (0.00s)
```

## `#[non_exhaustive]` result

- **Accepted.** `#[non_exhaustive]` stays on `ErrorCode`, `ApiError`, `Event`, `Network`, `Feature` and
  `Capabilities`. The derives compile without a change and without a warning (`clippy -D warnings` is clean).
  The derive code is generated inside `arachne-api`, where `non_exhaustive` has no effect. So the
  record lift (`Capabilities { .. }`) also compiles.
- Rust callers in other crates still need a `_` arm. The spike crate has a test for this.
- UniFFI does not carry it to foreign code. Kotlin `enum class`, Swift `enum` and Python `Enum` are
  exhaustive. A Swift `switch` without `default` compiles today and breaks when we add a variant.
  So the ADR rule stays: a new variant increments `API_VERSION`, and foreign code keeps
  `else`/`default`.

## Findings

1. **Kotlin: `close` clashes with `AutoCloseable.close`.** Each generated Kotlin object implements
   `AutoCloseable`. Its `close()` frees the native handle. An exported Rust `close` gives
   `error: conflicting overloads` in kotlinc. Workaround used: a Kotlin-only rename in the
   spike crate `uniffi.toml` (`[bindings.kotlin.rename] "SpikeClient.close" = "shutdown"`). The other
   languages keep `close`. For the ADR: choose one name for the session close in all languages
   (for example `shutdown`), or keep the rename. Good side: the ADR wants candidates to be
   `AutoCloseable` in Kotlin, and UniFFI gives that for free. `close()` drops the `Arc`, and Rust `Drop`
   can do the discard.
2. **Go: wrong wire values for enums with explicit discriminants (bug in `uniffi-bindgen-go` v0.7.1).**
   `ErrorCode` has `#[repr(u32)]` values (1, 2, 3, 100, 101, ...). The Go generator makes the constants
   from the discriminants (`ErrorCodeInvalidId = 101`). But its `Read`/`Write` use the value as the
   1-based variant index, as the wire format requires. Result: Rust `InvalidId` arrives in Go as
   `ErrorCode(5)`, and a Go constant sent to Rust fails with `Invalid ErrorCode enum value: 103`.
   Kotlin, Swift and Python map the index correctly. `bindgen-go-enum-discr.patch` changes the
   `EnumTemplate.go` template to map index to constant and back for enums with discriminants. With the
   patch, the Go test passes. Enums without discriminants (`Network`, `Event`) are not affected.
   Options: send the patch upstream (preferred), or keep a patched generator in the SDK build.
   A third option is to remove the explicit discriminants from `ErrorCode` and expose only `number()`.
   But then the generated Kotlin/Swift/Python enums lose the real numbers.
3. **`ApiError::code()` as a method does not reach every language.**
   - Go: `uniffi-bindgen-go` emits no methods on error types. `ApiError` has no `Code()`.
   - Python: in the variants `Storage`, `Transport`, `Authorization` and `State`, the field `code` hides
     the method `code()`. `e.code()` then fails with `TypeError: 'ErrorCode' object is not callable`.
   - Workaround used: the free function `api_error_code(&ApiError) -> ErrorCode`. It works in all four
     languages. Do not name it `error_code`: in Go that becomes `func ErrorCode`, which clashes with
     `type ErrorCode` in the same package.
   - For the ADR: export the code as a free function, or give every variant a `code` field.
     Keep `code()` in Rust.
4. **ID newtypes as custom types: validation works, but foreign types are not distinct.**
   `custom_type!` over a hex `String` keeps the Rust types as they are. A bad foreign string fails in
   `try_lift`. UniFFI 0.31 downcasts that error to `ApiError` when the function returns
   `Result<_, ApiError>`, so the caller gets a typed `InvalidId` (101). This is proven in all four
   languages (`describe_peer`). But foreign code sees `typealias EndpointId = String` (Kotlin),
   `typealias EndpointId = String` (Swift), `EndpointId = str` (Python) and `type EndpointId = string` (Go). So the ADR claim "you cannot
   mix them" is true in Rust only. If distinct foreign types are necessary, the options are a
   per-language `custom_types` wrapper in `uniffi.toml` (for example a Kotlin value class) or one
   `uniffi::Object` per ID kind. The spike recommends custom types for version 1.
5. **Library mode makes one module for each crate.** The cdylib gives two modules: `arachne_api` and
   `arachne_uniffi_spike`. Each language needs a small layout step:
   - Kotlin: two packages, `uniffi.arachne_api` and `uniffi.arachne_uniffi_spike`. Both load the one
     `.so` (`arachne_uniffi_spike`). Set `cdylib_name` for the real SDK name.
   - Swift: compile both generated `.swift` files into one module, with one `-fmodule-map-file` for each
     `*FFI.modulemap`.
   - Python: put the generated files in a package (they use `from . import arachne_api`).
   - Go: set `[bindings.go] go_mod` in `uniffi.toml` of the cdylib crate, so the spike package can
     import `arachne.spike/gen/arachne_api`.
6. **Blocking calls do not block other calls.** The generated code in all four languages holds no
   binding lock around `next_event`. `close()` and `wake()` run at the same time from other threads.
   This confirms the ADR claim that generated code fixes B10.

## Binding sizes

Generated lines (`wc -l`, not formatted):

| Language | `arachne_api` | spike object module | Total generated | Hand bindings today |
| --- | --- | --- | --- | --- |
| Kotlin | 1,730 | 1,641 | 3,371 | 690 (`Client.kt`) |
| Swift | 1,685 + 533 (.h) | 874 + 632 (.h) | 3,724 | 1,085 (`Client.swift`) |
| Python | 2,078 | 1,257 | 3,335 | 1,129 (`client.py`) |
| Go | 1,638 + 660 (.h) | 924 + 759 (.h) | 3,981 | 1,137 (`client.go`) |

- The generated files are larger than the hand bindings. Most of each file is fixed runtime code
  (buffers, converters, call status, handle map). Each crate module has its own copy of it. The spike
  surface is small, so almost all of these lines are fixed cost.
- The lines are not written, reviewed or maintained by hand. The hand-written binding lines go to 0
  (today: 4,041 in the four files above; the ADR counts about 4,400 with the Kotlin model files). The cost of a new op is one Rust function in each language.
- Do not commit generated files. Generate them in the SDK build.

## Recommendations for the ADR

1. Keep decision 1 (UniFFI proc-macro, `=0.31.x`). Pin `=0.31.2`. Build `uniffi-bindgen-go` from a
   checkout: run `cargo update -p uniffi_bindgen --precise 0.31.2` there, then install with `--locked`.
   Its own lock file has 0.31.0. The spike used 0.31.2 in both the scaffolding and the Go generator.
   The mix of a 0.31.0 generator with 0.31.2 scaffolding is not tested.
2. Before step 8 (Go), fix the Go enum discriminant bug upstream, or carry
   `bindgen-go-enum-discr.patch` in the SDK build. This is the only blocker that we found.
3. Export the error code as a free function (`api_error_code`) in addition to `code()` in Rust.
4. Do not export a method named `close` on objects for Kotlin. Use one name in all languages, or a
   Kotlin rename in `uniffi.toml`.
5. Keep the ID newtypes as custom types over hex `String` for version 1. Record in the ADR that they are
   distinct in Rust only.

## How to reproduce

```bash
# One time: generator and JNA (scratch paths are examples)
cargo install uniffi-bindgen-go --git https://github.com/NordSecurity/uniffi-bindgen-go \
    --tag v0.7.1+v0.31.0 --root /tmp/bgo        # stock generator (fails the Go test)
# Patched generator: in a checkout of tag v0.7.1+v0.31.0, apply
# crates/arachne-uniffi-spike/bindgen-go-enum-discr.patch (patch -p1), delete the
# rust-toolchain file (it pins 1.87; current dependencies need 1.88 or later), then:
#   cargo install --path bindgen --root /tmp/bgo-patched
curl -sLo /tmp/jna-5.17.0.jar https://repo1.maven.org/maven2/net/java/dev/jna/jna/5.17.0/jna-5.17.0.jar

JNA_JAR=/tmp/jna-5.17.0.jar BINDGEN_GO=/path/to/patched/uniffi-bindgen-go \
    crates/arachne-uniffi-spike/run.sh
```
