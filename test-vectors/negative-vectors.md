# Negative test vectors

Apply each mutation to decoded `one-chunk.pqbk.hex` bytes. Offsets include the four-byte header-length prefix. Unless stated otherwise, flip the low bit of the named field's first byte.

| ID | Mutation | Expected category |
| --- | --- | --- |
| N01 | Truncate before the four-byte header length completes | Truncated archive |
| N02 | Change archive magic at offset 4 | Invalid archive format |
| N03 | Change version at offsets 12–13 | Unsupported version |
| N04 | Set KEM ID at offsets 14–15 to zero | Unsupported algorithm |
| N05 | Set chunk size at offsets 20–23 to zero | Invalid structural field |
| N06 | Change root-key ID at offsets 32–47 | Root-key metadata mismatch |
| N07 | Change root-key epoch at offsets 48–51 | Root-key metadata mismatch |
| N08 | Change HKDF salt at offset 52 | Authentication failure |
| N09 | Change metadata nonce at offset 104 | Filename authentication failure |
| N10 | Change ML-KEM ciphertext at offset 120 | Authentication failure |
| N11 | Change encrypted filename ciphertext | Filename authentication failure |
| N12 | Change wrapped DEK ciphertext | DEK authentication failure |
| N13 | Change data-frame index from zero to one | Chunk sequence failure |
| N14 | Change final flag from one to zero | Authentication or missing-final failure |
| N15 | Change data ciphertext | Chunk authentication failure |
| N16 | Remove final byte | Truncated chunk |
| N17 | Append one byte | Unexpected trailing data |

Calculate variable-field offsets after the ML-KEM ciphertext from the format specification by reading the KEM, encrypted-filename, and wrapped-DEK lengths.

Exact error text is not an interoperability contract. Implementations must map failures to the listed category and must not emit a completed plaintext output. Phase 2 converts these recipes into an automated corruption corpus.

