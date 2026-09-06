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
- ML-DSA-87 signing seed: bytes `a0` through `bf`.
- Signer-key ID: bytes `81` through `90`.
- Signer-key epoch: `0x01020304`.

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
- `mlkem-seed.hex`: public deterministic ML-KEM seed for offline restore drills.
- `root-key.hex`: complete canonical `PQROOT02` key file as lowercase hex.
- `checksums.txt`: plaintext and component/archive hashes for all cases.
- `provenance-checksums.txt`: ML-DSA-87 public key, canonical statement,
  signature, and complete signed-archive SHA-256 values for the one-chunk case.
- `negative-vectors.md`: mutations and required error categories.

The Rust unit tests reconstruct each vector, compare all hashes, and compare
the complete unsigned one-chunk archive byte-for-byte. ML-DSA deterministic
signature hashes freeze the provenance domain, coverage, metadata statement,
and signature encoding. Any unintended byte-layout or domain-separator change
fails a test.
