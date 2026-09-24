// Spike test (ADR A1/A4 step 7): generated Kotlin bindings.
import uniffi.arachne_api.*
import uniffi.arachne_uniffi_spike.*
import kotlin.concurrent.thread

fun check(ok: Boolean, what: String) {
    if (!ok) { println("FAIL: $what"); kotlin.system.exitProcess(1) }
    println("ok: $what")
}

fun main() {
    val client = SpikeClient(Network.LAN)

    // 1. Result method: bad hex gives ApiException.InvalidId, code 101.
    try {
        client.parseEndpoint("zz")
        check(false, "parseEndpoint must throw")
    } catch (e: ApiException.InvalidId) {
        check(e.code().number() == 101u, "parseEndpoint error code = ${e.code().number()} (${e.code()})")
        check(e.code().value == 101u, "ErrorCode.value discriminant = ${e.code().value}")
    }

    // 2. Custom-type lift: a bad EndpointId argument gives a typed ApiException too.
    try {
        client.describePeer("not-hex")
        check(false, "describePeer must throw")
    } catch (e: ApiException.InvalidId) {
        check(e.code().number() == 101u, "describePeer lift error code = ${e.code().number()}")
    }
    val good = "ab".repeat(32)
    check(client.parseEndpoint(good) == good, "valid EndpointId round-trips as hex")

    // 3. Constructor error: Tor gives code 103.
    try {
        SpikeClient(Network.TOR)
        check(false, "Tor must throw")
    } catch (e: ApiException.State) {
        check(e.code().number() == 103u, "constructor error code = ${e.code().number()}")
    }

    // 4. Event and non_exhaustive record cross.
    client.pushEvent(Event.PRESENCE)
    check(client.nextEvent(1000uL) == Event.PRESENCE, "pushed Event.PRESENCE comes back")
    val caps = client.capabilities()
    check(caps.apiVersion == 1u && Network.TOR !in caps.networks, "capabilities record = $caps")

    // 5. wake() releases a waiter.
    var woke: Event? = Event.CLOSED
    val w = thread { woke = client.nextEvent(30_000uL) }
    Thread.sleep(200); client.wake(); w.join(2000)
    check(!w.isAlive && woke == null, "wake() released next_event")

    // 6. close() from another thread releases a parked next_event within 2 s.
    var got: Event? = Event.CLOSED
    var elapsedMs = -1L
    val waiter = thread {
        val t0 = System.nanoTime()
        got = client.nextEvent(30_000uL)
        elapsedMs = (System.nanoTime() - t0) / 1_000_000
    }
    Thread.sleep(200)
    thread { client.shutdown() }.join()  // Rust `close`, renamed for Kotlin (uniffi.toml)
    waiter.join(2000)
    check(!waiter.isAlive, "waiter returned after close()")
    check(got == null && elapsedMs in 0..1999, "next_event returned null after ${elapsedMs} ms")

    // 7. After close, calls give Closed (code 1).
    try {
        client.parseEndpoint(good)
        check(false, "call after close must throw")
    } catch (e: ApiException.Closed) {
        check(e.code().number() == 1u, "after close error code = ${e.code().number()}")
    }
    println("KOTLIN PASS")
}
