# Security model

**Status:** Experimental baseline  
**Applies to:** `PQBACK02` archives, optional `PQSIG001` provenance, and key/policy files
**Related:** [Supported limits](./SUPPORTED_LIMITS.md), [Risk register](./RISK_REGISTER.md), and [long-term assessment](./LONG_TERM_SECURITY_ASSESSMENT.md)

## Security objective

`pqbackup` is intended to preserve the confidentiality and detect modification of offline file archives, including against an attacker who copies encrypted archives now and attempts decryption later with quantum-capable technology.

Recovery intentionally requires two independently protected secret classes:

1. the 64-byte ML-KEM-1024 decapsulation seed; and
2. the `PQROOT02` file containing a 32-byte root secret.

A deployment only receives the intended defense in depth when those secrets are stored and backed up in separate failure domains.

## Protected assets

- Plaintext file contents.
- The original filename.
- The per-archive DEK and derived KEK.
- ML-KEM decapsulation seeds.
- Root-secret bytes.
- Availability of recovery materials and a compatible decoder.

The archive's approximate size, exact declared plaintext length, algorithms, chunk size, root-key ID, and root-key epoch are not confidential.

## Trust boundaries

### Trusted

- The host, kernel, process environment, random-number generator, and linked cryptographic libraries while sealing or opening.
- The operator selecting the intended input, output, and key paths.
- Separate custody locations for the ML-KEM seed and root key.
- The `pqbackup` binary and source/release materials used for recovery.
- The signer public key and `PQSIGNERS01` policy when provenance is evaluated.

### Untrusted

- Every `.pqbk` archive before full cryptographic verification.
- Archive filenames, directories, removable media, network storage, and transport.
- Header and signer values displayed by `inspect`.
- Any recovered filename until encrypted metadata authenticates.
- Demo-generated key layouts.

`inspect` parses public routing and self-asserted signer metadata without
recovery or verification keys. Its output is not authenticated and must not be
treated as authoritative proof of a key, epoch, creator, or archive history.

## Adversaries considered

- An attacker who obtains one or more encrypted archives.
- A future attacker capable of breaking or weakening ML-KEM while lacking the root secret.
- An attacker who modifies, truncates, reorders, appends to, substitutes, or replays archives.
- An operator who accidentally selects the wrong root-key epoch or recovery seed.
- Storage corruption and incomplete archive copies.

## Adversaries outside the current protection boundary

- Malware or a privileged attacker on the sealing or recovery host.
- An attacker who obtains both recovery secret classes.
- Physical coercion or compelled disclosure.
- Denial of service through deletion, substitution, or corruption.
- Traffic analysis or inference from visible file length and operational metadata.
- Side-channel attacks outside protections supplied by the operating system and dependencies.
- Supply-chain compromise of source, compiler, dependencies, or distributed binaries.
- Trusted creation time, newest-version selection, deletion detection, and
  rollback prevention without an external catalog or timestamp authority.

## Security properties

### Confidentiality

Content uses a fresh AES-256-GCM DEK. The DEK is wrapped by a KEK derived from the ML-KEM shared secret and independent root secret through HKDF-SHA-384. The filename is separately encrypted under the KEK.

### Integrity

AES-GCM authenticates encrypted filename metadata, the wrapped DEK, and every
data chunk. Chunk AAD binds the header hash, chunk index, plaintext length, and
final flag. Full verification rejects reordering, truncation, unsupported
trailing data, and authenticated-length mismatch. Exactly one canonical
provenance trailer may follow the encrypted envelope.

### Availability

The format detects corruption but cannot prevent deletion or replacement. Availability requires redundant archives, redundant copies of each secret class, preserved recovery software, and periodic restore tests.

### Provenance

The optional `PQSIG001` extension uses ML-DSA-87 to cover the complete encrypted
envelope and canonical signer metadata. `provenance-verify` attributes those
exact bytes to an identity only after a separately authenticated public key and
`PQSIGNERS01` policy bind the signer ID, epoch, fingerprint, identity, and
lifecycle state. Retired keys require explicit historical acceptance; revoked
keys are rejected.

This is creator authentication, not non-repudiation, trusted time, freshness,
or rollback prevention. Valid copies and older valid archives remain valid.
Those properties require an authenticated append-only catalog or trusted
timestamp that version 0.0.5 does not provide.

## Operational policy decisions

- The combined `keygen` command is removed. Production keys must be generated with separate `keygen-kem` and `keygen-root` operations at their intended custody locations.
- Demo mode may co-locate disposable secrets, but prints a warning and must never be used as a production key layout.
- Root-key epochs are deployment-defined. Annual rotation is the default recommendation; rotate immediately after suspected exposure or custody failure.
- Retain every old root key and ML-KEM seed while any required archive depends on it.
- Perform at least annual clean restore drills and review cryptographic status at least every two years.
- Migrate sooner when a dependency, construction, or standard receives a material security warning.

## Unsupported uses

- Sole backup or sole protection for irreplaceable data.
- Regulated or high-assurance use without separate review and applicable validation.
- Multi-user or remote decryption services exposed to hostile callers.
- Proof of creation time, freshness, uniqueness, or newest-backup status.
- Unattended production sealing that keeps both recovery secret classes online.
- Archives beyond the current enforced limits or the provisional Phase 2 targets.
- “Write once and forget” retention without periodic verification and migration.
