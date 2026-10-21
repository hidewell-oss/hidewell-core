#!/usr/bin/env bash
# Run the Swift package tests on an iOS simulator (after build-ios.sh).
# Usage: scripts/test-ios.sh ["iPhone 17e"]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/bindings/swift/HidewellCore"
xcodebuild -scheme HidewellCore -destination "platform=iOS Simulator,name=${1:-iPhone 17e}" test
