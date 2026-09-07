# Phase 6 independent security-review package

**Candidate:** `pqbackup` 0.0.6
**Format scope:** frozen `PQBACK02`, `PQROOT02`, and optional `PQSIG001`
**Review status:** not yet independently reviewed

This document is the brief for an independent reviewer. Repository tests and
the maintainer pre-review are evidence inputs, not a substitute for the review.
The reviewer must be independent of the design and implementation work.

## Required review scope

1. Cryptographic composition: ML-KEM-1024 plus the independent root secret,
   HKDF-SHA-384 domains, AES-256-GCM key wrapping and framing, nonce formation,
   encrypted metadata, and failure behavior.
2. Provenance: ML-DSA-87 signing scope, canonical statement, parser boundaries,
   signer ID/epoch binding, policy fingerprint binding, lifecycle behavior,
   substitution, replay, rollback, and revocation limitations.
3. Rust implementation: unsafe-code exposure in the dependency tree, integer
   and allocation bounds, secret lifetimes, zeroization limits, error paths,
   filesystem races, permissions, temporary-file publication, and denial of
   service.
4. Parser robustness: ambiguous encodings, truncation, extra bytes, unknown
   flags, nested trailers, non-canonical keys, and fuzzing coverage.
5. Side channels within scope: secret-dependent branches or memory access,
   observable error differences, timing boundaries, swap/dumps, and limitations
   inherited from dependencies and the operating system.
6. Operations: independent custody, inventory and policy integrity, rotation,
   irreversible compromise states, release provenance, rebuild, offline
   recovery, migration, and operator-error handling.

Out of scope only when explicitly recorded: physical intrusion, a fully
compromised endpoint during sealing or recovery, cryptanalysis of standardized
algorithms, and compliance certification. The report should still describe how
these exclusions limit its conclusions.

## Review inputs

- `src/main.rs` and `Cargo.lock`
- `docs/PQBACK02_FORMAT.md`, `docs/PQROOT02_FORMAT.md`, and
  `docs/PQBACK02_PROVENANCE_FORMAT.md`
- `docs/SECURITY_MODEL.md`, `docs/KEY_MANAGEMENT.md`, and
  `docs/PROVENANCE_POLICY.md`
- `docs/RISK_REGISTER.md` and `docs/LONG_TERM_SECURITY_ASSESSMENT.md`
- deterministic and negative fixtures in `test-vectors/`
- fuzz targets in `fuzz/fuzz_targets/`
- release/recovery scripts and `.github/workflows/rust.yml`
- `scripts/run-controlled-pilot.sh`

## Reproduction baseline

From the candidate commit:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
cargo deny check advisories bans licenses sources
./scripts/run-controlled-pilot.sh target/debug/pqbackup
./scripts/verify-release-build.sh "$(rustc -vV | sed -n 's/^host: //p')"
```

The release recovery kit must also pass the offline procedure in
`docs/RECOVERY_RUNBOOK.md`.

## Required report format

Every finding should include a stable ID, severity, affected code or document,
threat scenario, reproduction steps, impact, recommendation, and confidence.
Use Critical, High, Medium, Low, or Informational severity and state the rating
method. Record reviewed commit and dependency-lock digests. The final report
must state reviewer identity, relevant qualifications, independence, dates,
scope exclusions, and whether retesting covered each remediation.

The maintainer records every finding and disposition in
`docs/PHASE6_REMEDIATION.md`. No finding may disappear because it was disputed;
disputed and accepted findings require written rationale and a named risk owner.

## Acceptance gate

Production consideration remains blocked until:

- the external report covers the required scope;
- no Critical or High finding remains unresolved;
- fixes have regression tests and reviewer retest evidence;
- limitations and public claims match the final report; and
- the exact reviewed commit is traceable to the proposed release.

Dependency standardization is not implementation validation. NIST publishes
[FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) and
[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final); the selected RustCrypto
implementations and this composition still require review.
