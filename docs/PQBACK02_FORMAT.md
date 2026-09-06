# PQBACK02 archive format

**Status:** frozen version 2 specification  
**Byte order:** unsigned integers are big-endian  
**String encoding:** UTF-8  
**Cryptographic suite:** ML-KEM-1024, HKDF-SHA-384, AES-256-GCM with 128-bit tags

Normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** describe interoperability requirements.

## File layout

```text
u32 header_length
u8  header[header_length]
frame frames[]
```

`header_length` excludes its own four bytes. It MUST be no greater than 65,536. At least one data frame MUST follow the header.

## Header layout

Offsets are relative to the first byte after `header_length`.

| Offset | Size | Field | Required value / meaning |
| ---: | ---: | --- | --- |
| 0 | 8 | magic | ASCII `PQBACK02` |
| 8 | 2 | version | `2` |
| 10 | 2 | KEM ID | `1` = ML-KEM-1024 |
| 12 | 2 | KDF ID | `1` = HKDF-SHA-384 |
| 14 | 2 | AEAD ID | `1` = AES-256-GCM |
| 16 | 4 | chunk size | 1 through 16,777,216 |
| 20 | 8 | original length | plaintext byte length, at most 1,099,511,627,776 |
| 28 | 16 | root-key ID | opaque, stable identifier |
| 44 | 4 | root-key epoch | deployment-defined unsigned epoch |
| 48 | 32 | HKDF salt | random per archive |
| 80 | 8 | data nonce prefix | random per archive |
| 88 | 12 | DEK-wrap nonce | random per archive |
| 100 | 12 | filename-metadata nonce | random per archive |
| 112 | 4 | KEM ciphertext length | exactly 1568 |
| 116 | 1568 | ML-KEM ciphertext | FIPS 203 ML-KEM-1024 ciphertext |
| 1684 | 2 | encrypted filename length | filename UTF-8 length plus 16-byte tag |
| 1686 | variable | encrypted filename | AES-256-GCM ciphertext and tag |
| variable | 2 | wrapped DEK length | exactly 48 |
| variable | 48 | wrapped DEK | 32-byte DEK ciphertext and 16-byte tag |

The header MUST end immediately after the wrapped DEK. Extra header bytes are invalid.

## Root-key selection

The visible root-key ID and epoch select a candidate `PQROOT02` key. They are routing metadata until authenticated. A decoder MUST compare them to the supplied root-key file before recovery and MUST authenticate them through the AAD constructions below.

Root-key IDs provide no key entropy. Epoch interpretation belongs to deployment policy; the binary value is not a date unless that policy says so.

## KEK derivation

ML-KEM-1024 decapsulation produces a 32-byte shared secret.

```text
IKM  = mlkem_shared_secret[32] || root_secret[32]
salt = header.hkdf_salt
info = UTF8("pqbackup/v2/archive-kek/aes-256-gcm")
KEK  = HKDF-SHA-384-Expand(HKDF-Extract(salt, IKM), info, 32)
```

The two IKM components have fixed length and no embedded length fields.

## Public header encoding

`PUBLIC_HEADER` is the exact header prefix from offset 0 through the final ML-KEM ciphertext byte: bytes `header[0..1684]`.

### Filename encryption

```text
metadata_aad = UTF8("pqbackup/v2/metadata") || PUBLIC_HEADER
cipher       = AES-256-GCM(KEK)
encrypted_filename = cipher.encrypt(
    nonce     = filename_metadata_nonce,
    plaintext = filename UTF-8 bytes,
    aad       = metadata_aad
)
```

Before encryption, the filename MUST be a non-empty UTF-8 single path component of at most 4096 bytes. It MUST NOT contain path separators or resolve to a parent path. A decoder MUST validate the recovered value again before using it as a default output path.

The encrypted filename length is therefore 17 through 4112 bytes.

### DEK wrapping

```text
wrap_aad =
    UTF8("pqbackup/v2/wrap")
    || PUBLIC_HEADER
    || u16(encrypted_filename_length)
    || encrypted_filename

wrapped_dek = AES-256-GCM(KEK).encrypt(
    nonce     = dek_wrap_nonce,
    plaintext = DEK[32],
    aad       = wrap_aad
)
```

Changing algorithms, lengths, root metadata, nonces, KEM ciphertext, or encrypted filename causes DEK unwrap failure.

## Header hash

```text
header_hash = SHA-384(header)
```

The four-byte outer `header_length` is not hashed. The entire encoded header, including encrypted filename and wrapped DEK, is hashed.

## Data frames

Each frame is:

| Size | Field |
| ---: | --- |
| 4 | zero-based chunk index |
| 4 | plaintext length |
| 1 | flags |
| plaintext length + 16 | AES-256-GCM ciphertext and tag |

Only flag bit 0 is defined. It is `1` for the final frame and `0` otherwise. Undefined flag bits MUST be zero.

The plaintext length MUST be no greater than the declared chunk size. Non-final frames produced by this implementation are normally full-size, but decoders authenticate the declared length rather than assuming fullness.

### Data nonce

```text
nonce = data_nonce_prefix[8] || u32(chunk_index)
```

Indexes start at zero and increase by exactly one. Counter wrap is forbidden.
This implementation permits at most 1,048,576 frames under one DEK, so the
counter cannot approach its 32-bit wrap point. The random 64-bit prefix is fixed
for the archive and each distinct index therefore produces a distinct 96-bit
nonce under that archive's fresh DEK.

### Data AAD

```text
chunk_aad =
    UTF8("pqbackup/v2/data-chunk")
    || header_hash[48]
    || u32(chunk_index)
    || u32(plaintext_length)
    || u8(final ? 1 : 0)
```

```text
frame_ciphertext = AES-256-GCM(DEK).encrypt(
    nonce     = nonce,
    plaintext = chunk plaintext,
    aad       = chunk_aad
)
```

## Empty and final files

An empty file has exactly one frame with index 0, plaintext length 0, final flag 1, and a 16-byte GCM tag.

A non-empty file has one or more frames. Exactly one authenticated final frame MUST occur. It MUST be last. The sum of authenticated plaintext lengths MUST equal `original_length`. Any byte after the final frame is invalid.

## Decoder rejection requirements

A decoder MUST reject:

- wrong magic or version;
- unknown algorithm IDs;
- oversized/truncated headers or unexpected header bytes;
- invalid fixed or variable lengths;
- invalid chunk size;
- wrong root-key ID or epoch;
- KEM, filename, DEK-wrap, or chunk authentication failure;
- non-sequential indexes;
- plaintext length greater than chunk size;
- missing final frame, total-length mismatch, or trailing bytes;
- unsafe decrypted filename.

Authentication failures SHOULD be exposed through coarse error categories. Exact diagnostic text is not part of the format.
See [ERROR_CATEGORIES.md](./ERROR_CATEGORIES.md) for the canonical categories.

## Output behavior

Implementations MUST NOT expose a completed output file before all frames authenticate and the total length is checked. This implementation writes and synchronizes a unique same-directory temporary file, then atomically publishes it with a no-replace hard link after complete verification. It refuses to overwrite an existing destination and removes the temporary link after publication.

## Enforced operational ceiling

See [SUPPORTED_LIMITS.md](./SUPPORTED_LIMITS.md). This implementation rejects
plaintext over 1 TiB and archives requiring more than 2^20 data frames.

## Test vectors

See [../test-vectors/manifest.md](../test-vectors/manifest.md). The canonical one-chunk archive freezes every byte of this encoding.
