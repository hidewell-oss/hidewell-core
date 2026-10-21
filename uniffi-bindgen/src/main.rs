//! Local UniFFI bindgen pinned to the workspace uniffi version.
//! `cargo run -p uniffi-bindgen -- generate --library <lib> --language kotlin --out-dir <dir>`
fn main() {
    uniffi::uniffi_bindgen_main()
}
