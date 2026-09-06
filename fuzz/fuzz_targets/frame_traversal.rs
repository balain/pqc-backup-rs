#![no_main]
#![allow(dead_code)]

use libfuzzer_sys::fuzz_target;

mod pqbackup {
    include!("../../src/main.rs");

    pub fn fuzz(data: &[u8]) {
        if data.len() < 4 {
            return;
        }
        let raw_chunk_size = u32::from_be_bytes(data[..4].try_into().unwrap());
        let chunk_size = raw_chunk_size % 4096 + 1;
        let mut reader = std::io::Cursor::new(&data[4..]);
        for _ in 0..64 {
            match read_encrypted_frame(&mut reader, chunk_size) {
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
    }
}

fuzz_target!(|data: &[u8]| pqbackup::fuzz(data));
