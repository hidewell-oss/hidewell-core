#![no_main]
//! `decode_anchor` over arbitrary plaintext bytes (what an authenticated-but-hostile blob would
//! yield): must return `Ok`/`Err`, never panic.

use hidewell_core::fuzz_api;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = fuzz_api::decode_anchor(data);
});
