"""Spike test (ADR A1/A4 step 7): generated Python bindings."""
import sys
import threading
import time

from arachne.arachne_api import ApiError, ErrorCode, Event, Network, api_error_code
from arachne.arachne_uniffi_spike import SpikeClient


def check(ok, what):
    if not ok:
        print(f"FAIL: {what}")
        sys.exit(1)
    print(f"ok: {what}")


client = SpikeClient(Network.LAN)

# 1. Result method: bad hex gives ApiError.InvalidId, code 101.
try:
    client.parse_endpoint("zz")
    check(False, "parse_endpoint must raise")
except ApiError.InvalidId as e:
    check(e.code().number() == 101, f"parse_endpoint error code = {e.code().number()} ({e.code()})")
    check(e.code().value == 101, f"ErrorCode.value discriminant = {e.code().value}")

# 2. Custom-type lift: a bad EndpointId argument gives a typed ApiError too.
try:
    client.describe_peer("not-hex")
    check(False, "describe_peer must raise")
except ApiError.InvalidId as e:
    check(e.code().number() == 101, f"describe_peer lift error code = {e.code().number()}")
good = "ab" * 32
check(client.parse_endpoint(good) == good, "valid EndpointId round-trips as hex")

# 3. Constructor error: Tor gives code 103.
try:
    SpikeClient(Network.TOR)
    check(False, "Tor must raise")
except ApiError.State as e:
    # Spike finding: on variants with a `code` field, the field hides the
    # `code()` method in Python. Use the free function `api_error_code`.
    check(isinstance(e.code, ErrorCode), "State.code is the field, not the method")
    check(api_error_code(e).number() == 103, f"constructor error code = {api_error_code(e).number()}")

# 4. Event and non_exhaustive record cross.
client.push_event(Event.PRESENCE)
check(client.next_event(1000) == Event.PRESENCE, "pushed Event.PRESENCE comes back")
caps = client.capabilities()
check(caps.api_version == 1 and Network.TOR not in caps.networks, f"capabilities record = {caps}")

# 5. wake() releases a waiter.
box = {"ev": Event.CLOSED}
w = threading.Thread(target=lambda: box.update(ev=client.next_event(30_000)))
w.start(); time.sleep(0.2); client.wake(); w.join(2)
check(not w.is_alive() and box["ev"] is None, "wake() released next_event")

# 6. close() from another thread releases a parked next_event within 2 s.
res = {"ev": Event.CLOSED, "ms": -1}
def park():
    t0 = time.monotonic()
    res["ev"] = client.next_event(30_000)
    res["ms"] = int((time.monotonic() - t0) * 1000)
waiter = threading.Thread(target=park)
waiter.start(); time.sleep(0.2)
closer = threading.Thread(target=client.close); closer.start(); closer.join()
waiter.join(2)
check(not waiter.is_alive(), "waiter returned after close()")
check(res["ev"] is None and 0 <= res["ms"] < 2000, f"next_event returned None after {res['ms']} ms")

# 7. After close, calls give Closed (code 1).
try:
    client.parse_endpoint(good)
    check(False, "call after close must raise")
except ApiError.Closed as e:
    check(e.code().number() == 1, f"after close error code = {e.code().number()}")
print("PYTHON PASS")
