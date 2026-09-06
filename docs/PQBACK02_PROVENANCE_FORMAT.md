# PQBACK02 provenance extension

**Extension magic:** `PQSIG001`
**Extension version:** 1
**Signature algorithm:** ML-DSA-87 (FIPS 204)
**Introduced by:** `pqbackup` 0.0.5

This document specifies the optional creator-provenance trailer accepted after
an otherwise complete `PQBACK02` encrypted envelope. The encrypted header and
data-frame bytes remain unchanged. A signed archive is not readable by
pre-0.0.5 decoders because those decoders correctly reject all trailing bytes.

## Security purpose

The encrypted envelope proves integrity only to a holder of both recovery
secrets. The provenance extension lets a verifier identify the archive creator
under a separately distributed trust policy without holding either recovery
secret.

The signature does not prove creation time, freshness, uniqueness, or that an
archive is the newest archive. An external trusted timestamp or append-only
catalog is required for those properties.

## Numeric encoding

All integers are unsigned and big-endian. Lengths are byte counts. No padding,
optional fields, or alternate encodings are permitted.

## Trailer layout

The trailer begins immediately after the final encrypted data-frame tag.

| Offset | Length | Field | Required value |
| ---: | ---: | --- | --- |
| 0 | 8 | magic | ASCII `PQSIG001` |
| 8 | 2 | extension version | `1` |
| 10 | 2 | signature algorithm | `1` = ML-DSA-87 |
| 12 | 16 | signer-key ID | opaque stable 128-bit identifier |
| 28 | 4 | signer-key epoch | lifecycle epoch selected by operator |
| 32 | 8 | signed envelope length | offset of this trailer from start of file |
| 40 | 4 | signature length | `4627` |
| 44 | 4627 | ML-DSA-87 signature | canonical encoded signature |

The statement prefix is the first 44 bytes. The complete trailer is exactly
4671 bytes. A decoder accepts either no trailer or exactly one complete
trailer. Unknown versions, algorithms, lengths, partial trailers, second
trailers, and bytes after the signature are rejected.

The signed envelope length MUST equal the exact number of bytes from the first
four-byte `PQBACK02` header-length field through the final data-frame GCM tag.
This prevents unsigned prefixes, suffixes, or alternate coverage boundaries.

## Signed message

ML-DSA-87 signs this exact byte sequence:

```text
ASCII/bytes "pqbackup/provenance/v1\0"
|| archive[0 .. signed_envelope_length]
|| trailer_statement_prefix[0 .. 44]
```

The NUL byte at the end of the domain string is included. The signature uses
the standard deterministic ML-DSA-87 signing operation with an empty ML-DSA
context string. The implementation streams the message into ML-DSA's SHAKE256
message representative; it does not define an external ad-hoc prehash mode.

The coverage includes every public header byte, the encrypted filename, the
wrapped DEK, every chunk header and ciphertext/tag, plus the signer ID, epoch,
algorithm, version, coverage boundary, and signature length.

## Signing-key files

### `PQSIGN01` secret key

| Offset | Length | Field |
| ---: | ---: | --- |
| 0 | 8 | ASCII `PQSIGN01` |
| 8 | 2 | key format version `1` |
| 10 | 2 | algorithm `1` |
| 12 | 16 | signer-key ID |
| 28 | 4 | signer-key epoch |
| 32 | 32 | ML-DSA-87 seed |

Total: 64 bytes. The file is secret and is created with mode `0600` on
supported Unix systems.

### `PQPUBS01` public key

| Offset | Length | Field |
| ---: | ---: | --- |
| 0 | 8 | ASCII `PQPUBS01` |
| 8 | 2 | key format version `1` |
| 10 | 2 | algorithm `1` |
| 12 | 16 | signer-key ID |
| 28 | 4 | signer-key epoch |
| 32 | 2592 | canonical ML-DSA-87 verification key |

Total: 2624 bytes. A verifier binds its SHA-256 fingerprint, ID, and epoch to
an explicit `PQSIGNERS01` policy record.

## Canonical verification procedure

1. Strictly parse the `PQBACK02` header and every frame through one final frame.
2. Require total framed plaintext length to equal the declared length.
3. Strictly parse exactly one provenance trailer.
4. Require its signed length to equal the computed encrypted-envelope length.
5. Require the supplied `PQPUBS01` key ID and epoch to match the trailer.
6. Verify ML-DSA-87 over the exact signed message above.
7. Locate the same ID and epoch in a separately trusted policy.
8. Require the policy fingerprint to equal the supplied public key fingerprint.
9. Apply the policy lifecycle state as defined in
   [`PROVENANCE_POLICY.md`](./PROVENANCE_POLICY.md).

`inspect` may report that a signature is present and show its self-asserted ID
and epoch, but MUST label those values unverified. It does not display the
trusted human identity or the encrypted plaintext filename.

## Migration and compatibility

Signing is ciphertext-only and does not require recovery keys. Preserve the
unsigned source until the signed copy verifies. A signed archive can be turned
back into the original unsigned envelope by removing exactly the validated
trailer, but the CLI intentionally does not provide a stripping command.

To change the encrypted format or cryptographic suite, perform the normal
decrypt, authenticate, and reseal migration. To rotate only the signer, retain
the unsigned envelope or create a newly signed copy from an independently
verified unsigned source. The CLI rejects nested/double signatures.
