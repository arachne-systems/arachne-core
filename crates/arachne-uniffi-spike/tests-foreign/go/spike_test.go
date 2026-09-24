// Spike test (ADR A1/A4 step 7): generated Go bindings (uniffi-bindgen-go).
package spike_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	api "arachne.spike/gen/arachne_api"
	spike "arachne.spike/gen/arachne_uniffi_spike"
)

func asAPI(t *testing.T, err error) *api.ApiError {
	t.Helper()
	var e *api.ApiError
	if !errors.As(err, &e) {
		t.Fatalf("not an *ApiError: %T %v", err, err)
	}
	return e
}

func TestSpike(t *testing.T) {
	client, err := spike.NewSpikeClient(api.NetworkLan)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Destroy()

	// 1. Result method: bad hex gives ApiErrorInvalidId, code 101.
	_, err = client.ParseEndpoint("zz")
	e := asAPI(t, err)
	if !errors.Is(err, api.ErrApiErrorInvalidId) {
		t.Fatalf("want InvalidId, got %v", err)
	}
	code := api.ApiErrorCode(e)
	if code.Number() != 101 {
		t.Fatalf("code.Number() = %d", code.Number())
	}
	t.Logf("ok: ParseEndpoint error code = %d", code.Number())
	// uniffi-bindgen-go v0.7.1 bug: flat enums with explicit discriminants
	// use the discriminant as the Go constant but read and write the 1-based
	// variant index on the wire. This fails on stock v0.7.1 and passes with
	// bindgen-go-enum-discr.patch (see docs/reviews/spike-a1-uniffi.md).
	if uint32(code) != 101 || code != api.ErrorCodeInvalidId {
		t.Fatalf("Go ErrorCode value = %d, want 101 (ErrorCodeInvalidId)", uint32(code))
	}
	t.Logf("ok: Go ErrorCode value = %d == ErrorCodeInvalidId", uint32(code))
	// Go -> Rust direction: a Go constant must lower to the right variant.
	if n := api.ApiErrorCode(api.NewApiErrorState(api.ErrorCodeUnsupported, "x")).Number(); n != 103 {
		t.Fatalf("Go-made State{Unsupported} code = %d", n)
	}
	t.Logf("ok: Go-made ApiError lowers ErrorCodeUnsupported as 103")

	// 2. Custom-type lift: a bad EndpointId argument gives a typed ApiError too.
	_, err = client.DescribePeer("not-hex")
	if n := api.ApiErrorCode(asAPI(t, err)).Number(); n != 101 {
		t.Fatalf("describe code = %d", n)
	}
	t.Logf("ok: DescribePeer lift error code = 101")
	good := strings.Repeat("ab", 32)
	if id, err := client.ParseEndpoint(good); err != nil || id != good {
		t.Fatalf("round trip: %v %v", id, err)
	}

	// 3. Constructor error: Tor gives code 103.
	_, err = spike.NewSpikeClient(api.NetworkTor)
	if n := api.ApiErrorCode(asAPI(t, err)).Number(); n != 103 {
		t.Fatalf("constructor code = %d", n)
	}
	t.Logf("ok: constructor error code = 103 (%v)", err)

	// 4. Event and non_exhaustive record cross.
	if err := client.PushEvent(api.EventPresence); err != nil {
		t.Fatal(err)
	}
	if ev := client.NextEvent(1000); ev == nil || *ev != api.EventPresence {
		t.Fatalf("event = %v", ev)
	}
	caps := client.Capabilities()
	if caps.ApiVersion != 1 || slices.Contains(caps.Networks, api.NetworkTor) {
		t.Fatalf("caps = %+v", caps)
	}
	t.Logf("ok: capabilities record = %+v", caps)

	// 5. Wake() releases a waiter.
	woke := make(chan *api.Event, 1)
	go func() { woke <- client.NextEvent(30_000) }()
	time.Sleep(200 * time.Millisecond)
	client.Wake()
	select {
	case ev := <-woke:
		if ev != nil {
			t.Fatalf("wake gave %v", *ev)
		}
		t.Logf("ok: Wake() released NextEvent")
	case <-time.After(2 * time.Second):
		t.Fatal("Wake() did not release NextEvent")
	}

	// 6. Close() from another goroutine releases a parked NextEvent within 2 s.
	type result struct {
		ev      *api.Event
		elapsed time.Duration
	}
	done := make(chan result, 1)
	go func() {
		t0 := time.Now()
		ev := client.NextEvent(30_000)
		done <- result{ev, time.Since(t0)}
	}()
	time.Sleep(200 * time.Millisecond)
	closed := make(chan struct{})
	go func() { client.Close(); close(closed) }()
	<-closed
	select {
	case r := <-done:
		if r.ev != nil || r.elapsed >= 2*time.Second {
			t.Fatalf("after close: %v in %v", r.ev, r.elapsed)
		}
		t.Logf("ok: NextEvent returned nil after %d ms", r.elapsed.Milliseconds())
	case <-time.After(2 * time.Second):
		t.Fatal("waiter did not return after Close()")
	}

	// 7. After close, calls give Closed (code 1).
	_, err = client.ParseEndpoint(good)
	if !errors.Is(err, api.ErrApiErrorClosed) || api.ApiErrorCode(asAPI(t, err)).Number() != 1 {
		t.Fatalf("after close: %v", err)
	}
	t.Logf("ok: after close error code = 1")
	t.Logf("GO PASS")
}
