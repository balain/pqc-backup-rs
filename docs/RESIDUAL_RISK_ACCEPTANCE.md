# Deployment residual-risk acceptance template

This file is a template, not an acceptance. Copy it into the deployment's
controlled governance system and complete it for one narrowly defined use.
Do not commit names, signatures, sensitive system details, or custody locations.

```text
Decision identifier:
Decision date and review expiry:
Named accountable owner:
Deployment and data classification:
Permitted use:
Explicitly prohibited use:
Candidate commit, tag, and artifact hashes:
Independent security-review report and reviewed commit:
Unresolved findings and written dispositions:
Completed real-pilot evidence reference:
Recovery-time objective and observed restore time:
Independent custody controls:
External rollback/timestamp control, if required:
Applicable legal/compliance determination:
Residual risks accepted:
Compensating controls:
Migration and restore-drill owners/schedule:
Go/no-go decision:
Owner approval:
Independent approver:
```

At minimum, explicitly address endpoint compromise, loss of either recovery
secret class, unaudited dependencies, policy substitution, rollback/replay,
metadata leakage, platform/filesystem scope, long-term rebuild risk, and the
absence of validated cryptographic-module or compliance claims.

Acceptance does not waive the requirement to fix Critical or High independent
review findings. It expires when the candidate, dependency lockfile, deployment
scope, custody model, or relevant threat changes.
