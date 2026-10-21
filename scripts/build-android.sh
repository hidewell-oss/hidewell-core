#!/usr/bin/env bash
# Build jniLibs (arm64-v8a, armeabi-v7a, x86_64; minSdk 28) with cargo-ndk, regenerate
# the Kotlin bindings and assemble the AAR in bindings/kotlin/hidewell-core.
# Requires: cargo-ndk, rustup targets aarch64-linux-android armv7-linux-androideabi
# x86_64-linux-android, NDK 28.2, JDK 21.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$HOME/Library/Android/sdk/ndk/28.2.13676358}"
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
export JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk@21}"
MOD="$ROOT/bindings/kotlin/hidewell-core"

cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -P 28 -o "$MOD/src/main/jniLibs" \
  build --locked -p hidewell-ffi --release

# Kotlin bindings from the host library (same metadata on every target).
cargo build --locked -p hidewell-ffi --release
HOSTLIB="target/release/libhidewell_ffi.dylib"
[ -f "$HOSTLIB" ] || HOSTLIB="target/release/libhidewell_ffi.so"
rm -rf "$MOD/src/main/kotlin/com/sentrybrain/hidewell/core"
cargo run --locked -q -p uniffi-bindgen -- generate --library "$HOSTLIB" \
  --language kotlin --out-dir "$MOD/src/main/kotlin" --no-format

cd "$MOD"
./gradlew --no-daemon -q assembleRelease testDebugUnitTest \
  -PhostLibDir="$ROOT/target/release"
echo "OK: $MOD/build/outputs/aar"
