# Deterministic test-vector manifest

These vectors freeze the `PQBACK02` byte layout and cryptographic domain separation. All secret values are public test data and must never be used for real encryption.

## Fixed inputs

- ML-KEM seed: bytes `00` through `3f`.
- ML-KEM encapsulation randomness: bytes `40` through `5f`.
- Root-key ID: bytes `60` through `6f`.
- Root secret: bytes `70` through `8f`.
- HKDF salt: bytes `90` through `af`.
- Data nonce prefix: bytes `b0` through `b7`.
- DEK-wrap nonce: bytes `c0` through `cb`.
- Filename-metadata nonce: bytes `d0` through `db`.
- DEK: bytes `e0` through `ff`.
- Root-key epoch: `0x01020304`.

ML-KEM uses the fixed seed's derived encapsulation key and deterministic test-only encapsulation. Production code does not expose deterministic randomness.

## Cases

| Name | Filename | Plaintext | Chunk size | Coverage |
| --- | --- | --- | ---: | --- |
| empty | `empty.txt` | empty | 16 | Authenticated empty final chunk |
| one-chunk | `backup.txt` | `pqbackup vector one\n` | 64 | Complete canonical archive bytes |
| multi-chunk | `multi.bin` | bytes `00`–`27` | 13 | Four frames and final flag |
| unicode | `café-数据.txt` | `unicode filename\n` | 64 | UTF-8 encrypted filename |
| max-filename | 4095 `a` bytes plus `x` | `max name\n` | 64 | Maximum filename |

## Files

- `one-chunk.pqbk.hex`: complete canonical archive as lowercase hex.
- `root-key.hex`: complete canonical `PQROOT02` key file as lowercase hex.
- `checksums.txt`: plaintext and component/archive hashes for all cases.
- `negative-vectors.md`: mutations and required error categories.

The Rust unit test reconstructs each vector, compares all hashes, and compares the complete one-chunk archive byte-for-byte. Any unintended byte-layout or domain-separator change fails the test.
