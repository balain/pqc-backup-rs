# Phase 6 finding and remediation record

**Status:** maintainer pre-review completed; external findings pending
**Candidate:** 0.0.6

This record preserves findings rather than only listing remaining defects.
External reviewer entries must identify the reviewed commit and link to the
retained report. Empty external rows are not evidence that review occurred.

## Maintainer pre-review findings

| ID | Severity | Finding | Disposition | Regression evidence | Status |
| --- | --- | --- | --- | --- | --- |
| P6-I001 | Medium | Root inventory entries could move from `compromised` or `destroyed` back to `active`, and signer entries could move from `revoked` back to `trusted`. This made accidental policy rollback possible. | Lifecycle transitions are now monotonic. Root keys may progress from active to retired/compromised/destroyed; signer keys may progress from trusted to retired/revoked. A terminal or compromised state cannot regain authority; use a new epoch instead. | `lifecycle_transition_matrices_are_monotonic`; `inventory_records_no_secrets_and_locates_archive_epoch`; `signer_lifecycle_rejects_retired_by_default_and_always_rejects_revoked` | Fixed |
| P6-I002 | Low | The selected ML-KEM parser's rejection of non-canonical public-key material was not directly locked by a package regression test. | Added an all-`0xff` malformed public-key rejection test through the production `key-info` path. | `malformed_ml_kem_public_key_is_rejected` | Fixed |
| P6-I003 | Informational | A valid old or copied signed archive remains valid because the format has no trusted time or append-only state. | No format change. Documentation and tests preserve this intentional boundary; deployments needing freshness must use an authenticated external catalog. | `older_signed_archive_remains_valid_without_an_external_rollback_catalog` | Accepted/deferred |

## Dependency review snapshot

The candidate lockfile selects `ml-kem` 0.3.2 and `ml-dsa` 0.1.1. The locked
dependency policy check reports no advisory-policy failure at the review date.
The selected ML-DSA version is newer than the patched versions in published
RustCrypto advisories
[GHSA-hcp2-x6j4-29j7](https://github.com/RustCrypto/signatures/security/advisories/GHSA-hcp2-x6j4-29j7),
[GHSA-5x2r-hc65-25f9](https://github.com/RustCrypto/signatures/security/advisories/GHSA-5x2r-hc65-25f9),
and
[GHSA-h37v-hp6w-2pp8](https://github.com/RustCrypto/signatures/security/advisories/GHSA-h37v-hp6w-2pp8).
This is a version/advisory check, not an audit or proof that no vulnerability
exists.

## External findings register

No external report has been received. Add one row for every external finding:

| ID | Report | Severity | Summary | Decision | Fix commit/test | Reviewer retest | Owner |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Pending | Pending | Pending | Independent review not yet commissioned or received | Pending | Pending | Pending | Pending |

## Disposition rules

- Critical and High findings block production consideration until fixed and
  independently retested.
- A disputed finding remains in this register with both rationales.
- Accepted Medium or lower risk requires the deployment-specific owner and
  scope recorded in `docs/RESIDUAL_RISK_ACCEPTANCE.md`.
- Remediation must not silently change a frozen format. Follow
  `docs/FORMAT_COMPATIBILITY.md` and issue a new format version when required.
