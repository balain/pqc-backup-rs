#![no_main]
#![allow(dead_code)]

use libfuzzer_sys::fuzz_target;

mod pqbackup {
    include!("../../src/main.rs");

    pub fn fuzz(data: &[u8]) {
        if let Ok(text) = std::str::from_utf8(data) {
            let _ = decode_signer_policy(text);
        }
    }
}

fuzz_target!(|data: &[u8]| pqbackup::fuzz(data));
