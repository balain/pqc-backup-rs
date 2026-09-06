# Changelog

All notable security-relevant and user-visible changes are recorded here.

## Unreleased

## 0.0.3 - 2026-09-06

### Release automation

- Changed `v*` tag builds from temporary Actions artifacts to GitHub Releases with a packaged Linux x86-64 binary and SHA-256 checksum.

### Phase 3 key lifecycle and custody

- Added `key-info` validation for root keys, ML-KEM public keys, ML-KEM seeds, and archive routing headers without displaying secret bytes.
- Added matching SHA-256 public-key fingerprints for ML-KEM public/seed pairing.
- Added the bounded, secret-free `PQINVENTORY01` custody inventory with init, add, list, check, locate, and lifecycle status commands.
- Added optional root-key ID and epoch assertions to `seal` for safer automation.
- Added a root-secret provider boundary suitable for future non-exportable backends while retaining the file provider.
- Changed secret and inventory creation to apply Unix mode `0600` at file creation time.
- Added key lifecycle, rotation, compromise, destruction, provider, and independent recovery-drill guidance.
- Expanded the demo and test suite for inventory, key validation, redundant recovery copies, permissions, and root expectation failures.

## 0.0.2 - 2026-09-06

### Phase 2 hostile-input hardening

- Enforced maximum plaintext size of 1 TiB and at most 2^20 data frames per archive.
- Added checked arithmetic and bounded all archive-controlled header and frame allocations.
- Changed seal and restore to use restrictive same-directory temporary files, atomic no-replace publication, overwrite refusal, and failure cleanup.
- Reduced restore to one archive/KEM pass while keeping the encrypted filename as the default destination.
- Replaced deprecated AES-GCM nonce construction and enabled warning-free lint/build gates.
- Tightened filename validation without changing the frozen v2 Unicode byte representation.
- Added end-to-end, limit, corruption, truncation, key mismatch, path, collision, permission, storage-failure, and nonce-uniqueness tests.
- Added production-parser fuzz targets for headers, root keys, and frame traversal plus CI fuzz smoke runs.

### Phase 1 format baseline

- Froze byte-level specifications for `PQBACK02` and `PQROOT02`.
- Added a strict compatibility and migration policy plus canonical decoder error categories.
- Added deterministic vectors for empty, one-chunk, multi-chunk, Unicode-filename, and maximum-filename archives.
- Added complete canonical archive/root-key hex fixtures and component checksums.
- Added tests that fail on unintended format, cryptographic-domain, or fixture changes.
- Rejects undefined data-frame flag bits.

### Phase 0 safety baseline

- Marked the CLI and documentation as experimental and unaudited.
- Removed the combined `keygen` command so normal production workflows cannot generate both recovery secret classes together.
- Kept `demo` as a disposable teaching workflow and added an explicit runtime warning that its co-located keys are unsafe for real archives.
- Defined the threat model, trust boundaries, supported environments, retention policy, and unsupported use cases.
- Established provisional Phase 2 limits of 1 TiB plaintext and 2^20 data chunks per archive.
- Deferred sender authentication/provenance until a signing-key trust, distribution, rotation, and revocation model is approved.
- Added a risk register mapping assessment findings to owners, phases, and release gates.

The package remains a reference implementation and is not approved as the sole protection for critical data.
