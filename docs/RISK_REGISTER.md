# Risk register

**Owner role:** “Maintainer” means the project maintainer until a named owner is assigned.  
**Status values:** Open, Mitigated, Accepted/deferred, or External dependency.

| ID | Risk | Severity | Status | Owner | Planned control / evidence |
| --- | --- | --- | --- | --- | --- |
| R-001 | `ml-kem` 0.3.2 has no independent audit | High | External dependency | Maintainer | Track upstream; independent package review in Phase 6; do not claim validation. |
| R-002 | Custom formats lack byte-level specifications and stable vectors | High | Mitigated | Maintainer | Phase 1 added frozen format documents and deterministic positive/negative vectors. |
| R-003 | Hostile parser coverage is limited | High | Mitigated | Maintainer | Phase 2 added corruption/truncation/property tests, production-parser fuzz targets, ASan smoke campaigns, and CI fuzzing. Continue growing the corpus. |
| R-004 | Endpoint compromise exposes plaintext and active secrets | Critical | Accepted/deferred | Operator | Hardened recovery host and custody now; provider/memory controls in Phase 3. Cannot be eliminated in software alone. |
| R-005 | Co-locating both recovery secrets defeats separation | Critical | Mitigated | Operator | Combined `keygen` removed; separate commands and explicit demo warning implemented in Phase 0. |
| R-006 | Loss of either secret class makes archives unrecoverable | Critical | Open | Operator | Phase 3 added inventory tooling and a two-copy recovery-drill procedure; remains open until operators provision and exercise independent copies. |
| R-007 | No explicit conservative archive-size/chunk-count enforcement | High | Mitigated | Maintainer | Phase 2 enforces and boundary-tests 1 TiB plaintext and 2^20 data-frame ceilings. |
| R-008 | No creator authentication, timestamp, or rollback protection | Medium | Accepted/deferred | Product owner | Explicitly out of current scope; Phase 5 only after trust/revocation design. |
| R-009 | Visible length and routing metadata enable inference | Medium | Accepted/deferred | Product owner | Document exposure; padding/profile decision requires a future format design. |
| R-010 | `inspect` metadata may be attacker-controlled | Medium | Mitigated | Operator | CLI/docs label it unauthenticated routing data; recovery AEAD remains authoritative. |
| R-011 | Secret zeroization cannot prevent swap, dumps, or OS inspection | High | Open | Maintainer | Phase 3 documents host controls and added a non-exportable-provider boundary; memory locking and an approved hardware backend remain open. |
| R-012 | Filename portability and normalization rules are incomplete | High | Mitigated | Maintainer | Supported scope is macOS/Linux; v2 preserves UTF-8 without normalization and rejects unsafe single-component names, with path-misuse tests. |
| R-013 | Dependency or build supply-chain compromise | High | Open | Maintainer | Phase 4 pinned toolchain, vulnerability checks, SBOM, signed/reproducible releases. |
| R-014 | Future environment may not rebuild or run the decoder | Critical | Open | Maintainer | Phase 4 signed recovery kit and offline clean-room restore tests. |
| R-015 | Storage deletion, corruption, or replay remains possible | High | Accepted/deferred | Operator | Independent archive copies and catalogs; provenance option in Phase 5. |
| R-016 | No formal compliance or cryptographic-module validation | High | Accepted/deferred | Product owner | Prohibit such claims; deployment-specific compliance work after Phase 6. |
| R-017 | Demo mode intentionally co-locates disposable secrets | Medium | Mitigated | Maintainer | Prominent runtime warning and documentation; demo files must never become production keys. |
| R-018 | Supported filesystem/OS behavior is not broadly validated | Medium | Open | Maintainer | Phase 3 atomically creates Unix secret/inventory files with mode `0600` and tests permissions; broader platform/filesystem validation remains open. |

## Phase 0 disposition

Phase 0 establishes ownership and policy; it does not close risks assigned to later phases. The current release remains experimental. Production consideration is blocked by R-001/R-002/R-003/R-006/R-007/R-011/R-013/R-014 and the independent-review gate.

Review this register whenever a phase completes, a dependency changes, a security report arrives, or a new deployment environment is proposed.
