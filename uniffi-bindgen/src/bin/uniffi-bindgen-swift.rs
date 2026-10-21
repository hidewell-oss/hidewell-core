//! Swift bindgen (sources, headers, modulemap for an XCFramework).
//! `cargo run -p uniffi-bindgen --bin uniffi-bindgen-swift -- <lib> <out> --swift-sources --headers --modulemap`
fn main() {
    uniffi::uniffi_bindgen_swift()
}
