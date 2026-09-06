#![no_main]
#![allow(dead_code)]

use libfuzzer_sys::fuzz_target;

mod pqbackup {
    include!("../../src/main.rs");

    pub fn fuzz(data: &[u8]) {
        // Exercise arbitrary malformed prefixes.
        let mut reader = std::io::Cursor::new(data);
        let _ = read_optional_provenance(&mut reader, 1234);

        // Also force every input through the complete-trailer path so the
        // 4,627-byte fixed signature does not depend on corpus discovery.
        let statement = encode_provenance_statement(&[0x5a; SIGNER_KEY_ID_LEN], 7, 1234);
        let mut complete = Vec::with_capacity(PROVENANCE_STATEMENT_LEN + MLDSA87_SIGNATURE_LEN);
        complete.extend_from_slice(&statement);
        complete.resize(PROVENANCE_STATEMENT_LEN + MLDSA87_SIGNATURE_LEN, 0);
        for (index, byte) in data.iter().take(MLDSA87_SIGNATURE_LEN).enumerate() {
            complete[PROVENANCE_STATEMENT_LEN + index] = *byte;
        }
        let mut reader = std::io::Cursor::new(complete);
        let _ = read_optional_provenance(&mut reader, 1234);
    }
}

fuzz_target!(|data: &[u8]| pqbackup::fuzz(data));
