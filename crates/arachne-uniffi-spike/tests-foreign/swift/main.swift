// Spike test (ADR A1/A4 step 7): generated Swift bindings.
// Compiled in one module with the generated arachne_api.swift and
// arachne_uniffi_spike.swift.
import Foundation

func check(_ ok: Bool, _ what: String) {
    if !ok { print("FAIL: \(what)"); exit(1) }
    print("ok: \(what)")
}

final class Box<T>: @unchecked Sendable { var value: T; init(_ v: T) { value = v } }

let client = try! SpikeClient(network: .lan)

// 1. Result method: bad hex gives ApiError.InvalidId, code 101.
do {
    _ = try client.parseEndpoint(hex: "zz")
    check(false, "parseEndpoint must throw")
} catch let e as ApiError {
    guard case .InvalidId = e else { check(false, "wrong case \(e)"); exit(1) }
    check(e.code().number() == 101, "parseEndpoint error code = \(e.code().number()) (\(e.code()))")
    check(e.code().rawValue == 101, "ErrorCode.rawValue discriminant = \(e.code().rawValue)")
}

// 2. Custom-type lift: a bad EndpointId argument gives a typed ApiError too.
do {
    _ = try client.describePeer(peer: "not-hex")
    check(false, "describePeer must throw")
} catch let e as ApiError {
    check(e.code().number() == 101, "describePeer lift error code = \(e.code().number())")
}
let good = String(repeating: "ab", count: 32)
check(try! client.parseEndpoint(hex: good) == good, "valid EndpointId round-trips as hex")

// 3. Constructor error: Tor gives code 103.
do {
    _ = try SpikeClient(network: .tor)
    check(false, "Tor must throw")
} catch let e as ApiError {
    check(e.code().number() == 103, "constructor error code = \(e.code().number())")
}

// 4. Event and non_exhaustive record cross.
try! client.pushEvent(event: .presence)
check(client.nextEvent(timeoutMs: 1000) == .presence, "pushed Event.presence comes back")
let caps = client.capabilities()
check(caps.apiVersion == 1 && !caps.networks.contains(.tor), "capabilities record = \(caps)")

// 5. wake() releases a waiter.
let woke = Box<Event?>(.closed)
let wakeDone = DispatchSemaphore(value: 0)
Thread.detachNewThread { woke.value = client.nextEvent(timeoutMs: 30_000); wakeDone.signal() }
Thread.sleep(forTimeInterval: 0.2)
client.wake()
check(wakeDone.wait(timeout: .now() + 2) == .success && woke.value == nil, "wake() released next_event")

// 6. close() from another thread releases a parked next_event within 2 s.
let got = Box<Event?>(.closed)
let elapsedMs = Box<Int>(-1)
let done = DispatchSemaphore(value: 0)
Thread.detachNewThread {
    let t0 = Date()
    got.value = client.nextEvent(timeoutMs: 30_000)
    elapsedMs.value = Int(Date().timeIntervalSince(t0) * 1000)
    done.signal()
}
Thread.sleep(forTimeInterval: 0.2)
let closed = DispatchSemaphore(value: 0)
Thread.detachNewThread { client.close(); closed.signal() }
closed.wait()
check(done.wait(timeout: .now() + 2) == .success, "waiter returned after close()")
check(got.value == nil && elapsedMs.value >= 0 && elapsedMs.value < 2000, "next_event returned nil after \(elapsedMs.value) ms")

// 7. After close, calls give Closed (code 1).
do {
    _ = try client.parseEndpoint(hex: good)
    check(false, "call after close must throw")
} catch let e as ApiError {
    guard case .Closed = e else { check(false, "wrong case \(e)"); exit(1) }
    check(e.code().number() == 1, "after close error code = \(e.code().number())")
}
print("SWIFT PASS")
