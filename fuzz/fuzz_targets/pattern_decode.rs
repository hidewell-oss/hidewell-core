#![no_main]
//! Canonical pattern decoding (`Pattern::decode`) and UI-shaped input (`from_drawn`):
//! never panics, and a decoded pattern re-encodes to the exact input.

use arbitrary::Arbitrary;
use hidewell_core::{Pattern, strength};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    encoded: Vec<u8>,
    drawn: Vec<Vec<u8>>,
}

fuzz_target!(|input: Input| {
    if let Ok(p) = Pattern::decode(&input.encoded) {
        assert_eq!(&p.encode()[..], &input.encoded[..]);
        let _ = p.check_policy();
        let _ = strength::evaluate(&p);
    }
    if let Ok(p) = Pattern::from_drawn(input.drawn) {
        let _ = Pattern::decode(&p.encode()).expect("re-decodes");
        let _ = strength::evaluate(&p);
    }
});
