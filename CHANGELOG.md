# Changelog

All notable security-relevant and user-visible changes are recorded here.

## Unreleased

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
