#!/usr/bin/env bash
# Spike (ADR A1/A4 step 7): build the cdylib, generate Kotlin, Swift, Python
# and Go bindings, and run one test per language. Not production.
#
# Needs: kotlinc + java (sdkman), Swift (swiftly), uv, Go, and
# uniffi-bindgen-go v0.7.1+v0.31.0 on PATH or in $BINDGEN_GO, built with
# bindgen-go-enum-discr.patch (stock v0.7.1 fails the Go test on ErrorCode).
# JNA jar in $JNA_JAR.
# Output goes to $OUT (default: target/uniffi-spike). Each test has a 60 s cap.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$ROOT/crates/arachne-uniffi-spike"
OUT="${OUT:-$ROOT/target/uniffi-spike}"
JNA_JAR="${JNA_JAR:?set JNA_JAR to jna-5.17.0.jar}"
BINDGEN_GO="${BINDGEN_GO:-uniffi-bindgen-go}"
LIBDIR="$ROOT/target/debug"
LIB="$LIBDIR/libarachne_uniffi_spike.so"

cd "$ROOT"
cargo build -q -p arachne-uniffi-spike
rm -rf "$OUT" && mkdir -p "$OUT"

gen() { cargo run -q -p arachne-uniffi-spike --bin uniffi-bindgen -- \
    generate --library "$LIB" --no-format --language "$1" --out-dir "$OUT/$1"; }

status=0
run() { local name=$1; shift; echo "== $name"; if ! timeout 60 "$@"; then echo "$name FAILED"; status=1; fi; }

# Kotlin
gen kotlin
( set +u; source "$HOME/.sdkman/bin/sdkman-init.sh"
  kotlinc "$OUT"/kotlin/uniffi/*/*.kt "$HERE/tests-foreign/kotlin/SpikeTest.kt" \
      -cp "$JNA_JAR" -include-runtime -d "$OUT/spike-kt.jar" 2>&1 | grep -v '^warning' || true )
run kotlin java -Djna.library.path="$LIBDIR" -cp "$OUT/spike-kt.jar:$JNA_JAR" SpikeTestKt

# Swift (one module: both generated files plus the test)
gen swift
( set +u; source "$HOME/.local/share/swiftly/env.sh"
  cd "$OUT/swift"
  swiftc -module-name SpikeTest -swift-version 6 \
      -Xcc -fmodule-map-file="$PWD/arachne_apiFFI.modulemap" \
      -Xcc -fmodule-map-file="$PWD/arachne_uniffi_spikeFFI.modulemap" \
      arachne_api.swift arachne_uniffi_spike.swift "$HERE/tests-foreign/swift/main.swift" \
      -L "$LIBDIR" -larachne_uniffi_spike -o "$OUT/spike-swift" )
run swift env LD_LIBRARY_PATH="$LIBDIR" "$OUT/spike-swift"

# Python (generated modules use relative imports, so they live in a package)
gen python
mkdir -p "$OUT/python/arachne"
mv "$OUT"/python/*.py "$OUT/python/arachne/"
touch "$OUT/python/arachne/__init__.py"
cp "$LIB" "$OUT/python/arachne/"
run python env PYTHONPATH="$OUT/python" uv run --no-project python "$HERE/tests-foreign/python/test_spike.py"

# Go
"$BINDGEN_GO" "$LIB" --out-dir "$OUT/go/gen"
cp "$HERE/tests-foreign/go/go.mod" "$HERE/tests-foreign/go/spike_test.go" "$OUT/go/"
( cd "$OUT/go"
  export CGO_ENABLED=1 CGO_LDFLAGS="-L$LIBDIR -larachne_uniffi_spike" LD_LIBRARY_PATH="$LIBDIR"
  run go go test -count=1 -v . ; exit $status ) || status=1

exit $status
