# Long-term security assessment

**Assessment date:** 2026-09-05  
**Assessed revision:** `PQBACK02` / `PQROOT02`  
**Scope:** local archival confidentiality and recoverability. This is a source review, not an independent audit, certification, or security guarantee.

## Executive assessment

`pqbackup` has a sound *experimental* long-term confidentiality design for a single-user, offline-backup threat model. Every archive requires two independent secret classes: an ML-KEM-1024 decapsulation seed and a separately held 256-bit root secret. An attacker who harvests encrypted archives today does not obtain the root secret, so a future break of ML-KEM alone should not reveal the archive DEK.

This is suitable for evaluation and defense-in-depth copies whose plaintext and recovery materials already have careful custody. It is **not appropriate as the sole protection for irreplaceable, regulated, or high-value data**. The limiting factors are the unaudited ML-KEM implementation, custom-format maturity, raw local key handling, absent independent review, and the operational challenge of preserving keys and a working decoder for decades.

## Security capabilities

### Harvest-now, decrypt-later resistance

For every archive, the package creates a 256-bit DEK and encrypts chunks with AES-256-GCM. It combines an ML-KEM-1024 shared secret and a separate 32-byte root secret using HKDF-SHA-384, then uses the result to wrap the DEK.

[NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) standardizes ML-KEM and describes it as believed secure against quantum-capable adversaries; ML-KEM-1024 is its largest standard parameter set. If a future attacker could derive the ML-KEM shared secret from a stored archive, the attacker would still need the root secret to derive the KEK.

Describe the symmetric margin conservatively: a 256-bit root secret and AES-256 are extremely strong classically, but under the usual generic quantum-search model their effective work factor is commonly treated as roughly 128 bits. That remains a substantial archival margin, but is the likely generic post-quantum limit of this two-factor construction.

### Content integrity and recovery safety

Each archive uses fresh KEM encapsulation, salt, DEK, nonce prefix, and wrap nonce. Chunk AAD binds the complete header hash, index, plaintext length, and final flag. The decoder rejects sequence errors, excess lengths, unauthenticated truncation, and trailing data. Restore writes to a temporary file and publishes it without replacement only after successful complete authentication.

AES-GCM requires unique nonces for each key; NIST calls this crucial in [SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final). A fresh DEK plus a 64-bit random prefix and 32-bit chunk index provide distinct nonce values within a non-overflowing archive.

### Metadata privacy and rotation support

`PQBACK02` encrypts and authenticates the original filename. `inspect` leaves it encrypted and reports only format/algorithm details, plaintext length, chunk size, root-key ID, root-key epoch, and envelope sizes. The root-key ID and epoch are bound into encrypted filename metadata and DEK wrapping, making them useful operational selectors for key rotation.

They are not secret entropy and do not prove the identity of whoever sealed an archive.

## Material risks and limitations

### Unaudited cryptographic implementation

The lockfile selects `ml-kem` 0.3.2. Its own [documentation](https://docs.rs/crate/ml-kem/0.3.2) says the implementation has never been independently audited. FIPS 203 standardization does not validate this particular Rust implementation. The root secret reduces the impact of a KEM confidentiality failure but does not eliminate implementation bugs, side channels, malformed-input behavior, or denial-of-service concerns.

### Endpoint compromise and secret handling

During sealing, the process can access plaintext, the root key, and derived keys. During recovery, it accesses both recovery secrets and plaintext. Malware, a compromised operating system, a privileged debugger, or malicious backup software at those moments defeats the intended protection.

The code uses `zeroize` for several explicit secret buffers, which is helpful, but cannot guarantee removal of compiler copies, swap, crash dumps, process inspection, or operating-system compromise. There is no memory locking, HSM, smartcard, platform-keystore, or non-exportable-key support.

### Key custody dominates the outcome

The ML-KEM seed and `PQROOT02` root-key file are sufficient recovery material. They must not be kept in the same cloud drive, password manager, USB device, system backup, or directory as the encrypted archive. The combined `keygen` command has been removed. The `demo` command still co-locates disposable secrets for convenience and is not a production custody pattern.

Header ID/epoch values are visible and not authenticated until recovery reaches the AEAD checks. Treat `inspect` results from an untrusted archive as routing information, not authoritative key provenance.

### No sender authentication, provenance, or rollback protection

AES-GCM authenticates an archive to someone holding the recovery capability; it does not prove who created it. There is no digital signature, trusted timestamp, append-only log, or replay/rollback control. An attacker who can substitute, delete, or replay archives can still cause availability and provenance failures.

### Metadata and denial-of-service exposure

Filename privacy is good, but plaintext length, chunk size, algorithms, root-key ID, and epoch remain visible. Length can expose approximate content type or backup cadence. An attacker can also corrupt clear header data to cause an early failure. Neither issue reveals plaintext, but both matter operationally.

### Immature custom-format assurance

The format is bespoke. It has small unit coverage and a command-line demo, but does not yet have a published byte-level specification, stable test vectors, independent implementation, parser fuzzing, corruption corpus, signed release, or dependency-vulnerability CI. Explicit algorithm IDs help future migration but do not implement algorithm agility.

### Archive-size bounds need formalization

The 32-bit chunk index prevents nonce wrap by failing on overflow, but the implementation does not enforce a conservative total archive-size or chunk-count limit. GCM has usage bounds as well as nonce-uniqueness requirements. Before supporting very large archives, define and enforce a maximum chunk count and plaintext size based on the chosen chunk size and accepted GCM limits.

### Multi-decade recovery is not automatic

Future recovery needs a compatible decoder, the ML-KEM seed, the matching root key, the format rules, and working dependencies. `Cargo.lock` helps, but no release artifact, formal specification, or preserved test vector is currently part of the recovery plan.

## Capability matrix

| Property | Assessment | Required condition |
| --- | --- | --- |
| Archive theft today | Strong confidentiality | Both recovery secrets stay unavailable. |
| Future ML-KEM break | Strong defense in depth | The independent root secret stays secret. |
| Generic PQ symmetric margin | Approximately 128-bit class | Standard generic quantum-search assumptions. |
| Content tamper detection | Strong | Complete decoder checks succeed. |
| Filename privacy | Good | File length and routing metadata remain visible. |
| Sender identity | Absent | No signature or provenance system exists. |
| Endpoint-compromise resistance | Weak | Secrets/plaintext enter the local process. |
| Compliance readiness | Insufficient | No validation or independent audit evidence. |
| Multi-decade recoverability | Moderate to weak | Active preservation and migration are required. |

## Recommended improvements

1. Do not rely on this as the only copy of critical data; maintain independent, tested backups and physically separated recovery materials.
2. Obtain an independent cryptographic/Rust review of the envelope, parser, error paths, secret handling, and command-line filesystem behavior.
3. Publish a versioned byte-level format specification, stable test vectors, and known-good release binaries with recovery instructions.
4. Add end-to-end corruption tests, parser fuzzing, dependency monitoring, reproducible builds, and release/CI policy.
5. Define and enforce conservative AES-GCM archive-size and chunk-count limits.
6. Deprecate the combined key-generation flow for production use and consider OS keystores, HSM/smartcard workflows, and memory-locking.
7. Add a canonical signed envelope only if creator identity and provenance are required, along with signing-key distribution and rotation policy.
8. Create a scheduled migration procedure: periodically decrypt, verify, and reseal archives with reviewed software while retaining old keys and decoders.

## Bottom line

The two-secret construction can materially reduce harvest-now, decrypt-later risk when strict offline separation is actually maintained. The package's long-term risk today is dominated by engineering assurance, endpoint exposure, key custody, and recovery practice rather than its use of AES-256, HKDF-SHA-384, or ML-KEM-1024. Treat it as a promising prototype requiring formalization, testing, and independent review before protecting data whose disclosure or loss would be unacceptable.
