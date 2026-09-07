# Production-readiness statement

**Candidate:** 0.0.6
**Decision date:** 2026-09-06
**Overall decision:** **NO-GO for production; GO only for constrained
experimental and controlled-pilot use.**

## Allowed scope

The candidate may be used for demonstrations, interoperability testing, and
non-authoritative defense-in-depth copies of non-critical data when the data is
independently recoverable without `pqbackup`. The warning, separate recovery
custody, verification, and retained recovery-kit requirements all apply.

## Prohibited scope

Do not use this candidate as the sole protection or sole recoverable copy for
irreplaceable, regulated, high-value, safety-critical, or operationally critical
data. Do not claim independent audit, formal verification, FIPS module
validation, compliance approval, trusted time, rollback prevention, endpoint
compromise resistance, or guaranteed multi-decade recovery.

## Gate status

| Gate | Status | Evidence or blocker |
| --- | --- | --- |
| Frozen candidate formats and vectors | Pass | Phase 1 specifications and regression vectors |
| Hostile-input and bounded-parser engineering | Pass for internal gate | Unit tests, fuzz targets, and CI smoke campaigns |
| Reproducible/recoverable release engineering | Pass for internal gate | Phase 4 release and recovery-kit workflow |
| Automated non-critical pilot | Pass | `docs/CONTROLLED_PILOT.md` |
| Maintainer pre-review remediation | Pass | `docs/PHASE6_REMEDIATION.md` |
| Independent security review | **Blocked** | No external report or reviewer retest evidence |
| Real separated-custody clean-room pilot | **Blocked** | Directory simulation is not physical/organizational separation |
| Deployment-specific risk acceptance | **Blocked** | No exact deployment or named accountable owner |
| Compliance/validated-module determination | **Blocked** | Separate analysis and validation required |

## Production reconsideration conditions

Reconsider one exact deployment only after all blocked gates are complete, no
Critical or High review finding remains, and the named owner signs a completed
copy of `docs/RESIDUAL_RISK_ACCEPTANCE.md`. A code or dependency change after
review requires impact analysis and may require targeted or complete re-review.

This statement deliberately limits claims to the evidence currently present in
the repository. It is not a product certification or general authorization.
