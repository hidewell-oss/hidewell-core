#!/usr/bin/env bash
# Build HidewellCoreFFI.xcframework (device arm64 + simulator arm64/x86_64) and
# regenerate the Swift bindings in bindings/swift/HidewellCore.
# Usage: scripts/build-ios.sh            (from anywhere)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export IPHONEOS_DEPLOYMENT_TARGET=16.0
PKG="$ROOT/bindings/swift/HidewellCore"
GEN="$ROOT/target/uniffi-swift"
LIB=libhidewell_ffi.a

for t in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
  cargo build --locked -p hidewell-ffi --release --target "$t"
done

# Bindings are generated from the host library (same metadata on every target).
cargo build --locked -p hidewell-ffi --release
rm -rf "$GEN" && mkdir -p "$GEN/include"
BINDGEN=(cargo run --locked -q -p uniffi-bindgen --bin uniffi-bindgen-swift --)
"${BINDGEN[@]}" target/release/libhidewell_ffi.dylib "$GEN" --swift-sources
"${BINDGEN[@]}" target/release/libhidewell_ffi.dylib "$GEN/include" --headers \
  --modulemap --module-name HidewellCoreFFI --modulemap-filename module.modulemap

mkdir -p "$PKG/Sources/HidewellCore"
cp "$GEN/HidewellCore.swift" "$PKG/Sources/HidewellCore/HidewellCore.swift"

SIM="$ROOT/target/ios-sim-universal"
mkdir -p "$SIM"
lipo -create target/aarch64-apple-ios-sim/release/$LIB target/x86_64-apple-ios/release/$LIB \
  -output "$SIM/$LIB"

rm -rf "$PKG/HidewellCoreFFI.xcframework"
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/$LIB -headers "$GEN/include" \
  -library "$SIM/$LIB" -headers "$GEN/include" \
  -output "$PKG/HidewellCoreFFI.xcframework"
echo "OK: $PKG"
