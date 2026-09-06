#![no_main]
#![allow(dead_code)]

use libfuzzer_sys::fuzz_target;

mod pqbackup {
    include!("../../src/main.rs");

    pub fn fuzz(data: &[u8]) {
        let _ = decode_header(data);
    }
}

fuzz_target!(|data: &[u8]| pqbackup::fuzz(data));
