# Security and compliance work requiring external activity

**Scope:** evidence or decisions that the project owner cannot legitimately
self-issue

## Purpose

This document identifies external activities required to support independent
security, trusted-time, validated-module, or regulatory claims. The project
owner can commission, fund, schedule, and respond to these activities, but the
result must come from an appropriately independent or authorized party.

Owner-controlled preparation is listed in
`docs/OWNER_CONTROLLED_SECURITY_WORK.md`.

## 1. Independent application security review

### External party

Engage a reviewer who did not design or implement the candidate. The reviewer
should have relevant experience in applied cryptography, Rust, hostile parsers,
filesystem security, key management, and recovery operations.

### Required scope

- ML-KEM plus root-secret composition and HKDF domains;
- AES-GCM nonce, wrapping, metadata, and chunk framing;
- ML-DSA signed representation and trust policy;
- proposed catalog canonicalization, chain/checkpoint design, and state
  transitions;
- integer, allocation, parsing, and denial-of-service boundaries;
- filesystem races, permissions, and failure cleanup;
- secret handling and side-channel limitations;
- provider or validated-module boundary;
- key custody, rotation, compromise, and recovery procedures; and
- public documentation and security claims.

### Required evidence

- reviewer identity, qualifications, independence statement, and dates;
- exact commit and dependency-lockfile digest;
- scope and exclusions;
- stable finding IDs, severity method, reproduction, impact, and recommendation;
- written disposition for every finding; and
- independent retest results for every material remediation.

Production consideration remains blocked while a Critical or High finding is
unresolved or has not been independently retested.

## 2. Trusted timestamp or independent catalog witness

### Why external activity is needed

A catalog signature proves authorization and integrity, not objective time. A
signed checkpoint stored only with the archive can be rolled back with the
archive. Independent time or broader equivocation evidence requires a party or
system outside that failure domain.

### Timestamp Authority option

An external Time-Stamping Authority can issue a signed token binding a catalog
checkpoint digest to a time assertion. RFC 3161 defines requests and responses
for proving that a datum existed before a particular time. See
[RFC 3161](https://www.rfc-editor.org/info/rfc3161/).

Required external evidence:

- TSA identity and certificate chain;
- timestamp policy identifier;
- retained response token and request digest;
- certificate status/revocation evidence appropriate to long-term validation;
- trusted time-source and retention policy information; and
- successful offline or long-term verification procedure.

A timestamp token does not identify the newest archive or prove that another
archive was not deleted. It should timestamp an authenticated catalog
checkpoint, not replace the catalog.

### Witness or transparency option

One or more independent witnesses can retain signed checkpoints and compare
successive states. A transparency service may provide inclusion and consistency
proofs. RFC 9162 describes Merkle consistency proofs that demonstrate one tree
extends an earlier tree, while also noting that inconsistent views require
monitoring or witness comparison. See
[RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html).

Required external evidence:

- witnessed checkpoint and receipt;
- inclusion and consistency proof when applicable;
- witness key and trust policy;
- monitoring or gossip procedure for detecting split views;
- availability and retention commitments; and
- an emergency verification path if the service disappears.

An organizationally separate internal custodian can improve rollback
resistance, but it is not an external trusted-time claim.

## 3. Cryptographic algorithm validation

### External parties

Cryptographic algorithm testing is performed through the Cryptographic
Algorithm Validation Program and its Automated Cryptographic Validation
Protocol infrastructure. The project cannot issue its own algorithm validation
certificate.

NIST explains that algorithm validation is required for algorithms listed as
approved functions on a module certificate, but algorithm validation alone does
not satisfy module validation. See the
[NIST CAVP overview](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program).

### Required decisions and evidence

- the implementation and module boundary submitted for testing;
- supported algorithm, mode, parameter, and revision combinations;
- prerequisite validations;
- test-vector responses accepted by the validation system;
- resulting algorithm certificate references; and
- mapping from tested implementation to the shipped module.

NIST's ACVP documentation includes ML-KEM and ML-DSA test specifications, but
availability and transition rules must be confirmed with the selected testing
laboratory for the actual submission. See
[NIST ACVP documentation](https://pages.nist.gov/ACVP/).

## 4. FIPS 140-3 cryptographic-module validation

### External parties

For a new validation, the vendor works with an NVLAP-accredited Cryptographic
and Security Testing Laboratory. The laboratory tests the module and submits
evidence for CMVP review. Only CMVP can issue the validation certificate.

NIST describes CMVP as the joint U.S./Canadian validation authority and states
that accredited laboratories test modules against the program requirements.
See the [CMVP overview](https://csrc.nist.gov/Projects/cryptographic-module-validation-program)
and [FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final).

### Route A: incorporate an existing validated module

External evidence must establish:

- an active CMVP certificate number;
- exact module name and version;
- approved operating environments and processor architectures;
- approved algorithms, modes, parameters, and caveats;
- required configuration and approved-mode indicator;
- module security policy;
- vendor support and change-notification policy; and
- confirmation that the integration does not modify or bypass the validated
  module boundary.

The official source of certificate status is the
[CMVP validated-module search](https://csrc.nist.gov/Projects/Cryptographic-Module-Validation-Program/Validated-Modules).

NIST permits incorporation of another vendor's validated module, but the
containing product cannot claim that it is itself validated. Its wording must
follow the permitted usage and the module's security policy. See the
[CMVP FAQ](https://csrc.nist.gov/Projects/cryptographic-module-validation-program/faqs).

### Route B: validate a pqbackup module

External work includes:

1. contract and scoping with an accredited laboratory;
2. laboratory review of the proposed module boundary and security level;
3. algorithm prerequisite testing;
4. examination of roles, services, interfaces, authentication, and state;
5. sensitive-security-parameter generation, entry, output, storage, and
   destruction review;
6. entropy-source and random-generation assessment;
7. software integrity, self-test, error-state, and lifecycle testing;
8. review of operating environments and physical/hybrid assumptions;
9. examination of vendor evidence and the module security policy;
10. remediation and retesting;
11. laboratory submission to CMVP; and
12. CMVP review and certificate issuance.

The external laboratory must specifically evaluate whether the custom
ML-KEM-shared-secret plus independent-root-secret HKDF composition can operate
as an approved service. The project must not infer approval merely because its
individual primitives are standardized.

### Evidence required before making claims

- final CMVP certificate and status;
- final module security policy;
- algorithm certificate references;
- exact validated binary/module version;
- approved operating environments;
- approved-mode configuration and indicator;
- documented caveats and excluded services;
- traceability from release artifact to validated module; and
- change-impact or revalidation procedure.

## 5. Regulatory or contractual compliance assessment

### Why module validation is not enough

FIPS 140-3 addresses a cryptographic module. It does not by itself establish
that an entire backup product, operating environment, organization, or
deployment complies with another framework.

An appropriate compliance professional, assessor, legal adviser, contracting
authority, or customer security authority must determine which requirements
apply and whether the evidence satisfies them.

### Potential external scope

- system and authorization boundary;
- data classification and retention obligations;
- access control and separation of duties;
- audit logging and evidence retention;
- incident response and breach notification;
- vulnerability and patch management;
- supplier and software supply-chain controls;
- backup, continuity, and disaster recovery;
- physical and personnel security;
- privacy and data-location requirements;
- cryptographic-module and algorithm requirements;
- penetration testing or other technical assessment; and
- periodic audit, attestation, or authorization.

### Required deliverable

Obtain a written, deployment-specific determination identifying:

- governing framework, contract, law, or policy;
- assessed system boundary and version;
- controls tested and evidence reviewed;
- findings and corrective actions;
- accepted exceptions and accountable owner;
- permitted claims;
- approval or attestation period; and
- reassessment triggers.

Generic statements such as “HIPAA compliant,” “FedRAMP ready,” or “government
approved” are not substitutes for that determination.

## 6. Independent operational observation

Some deployment policies require an external or organizationally independent
observer for recovery and custody drills. When required, the observer should
verify:

- real separation of ML-KEM and root-key custody;
- independent copies and failure domains;
- clean-system and offline recovery;
- each custody-copy combination;
- elapsed recovery time and operator mistakes;
- checkpoint retrieval and stale-archive detection;
- software/recovery-kit authentication;
- compromise and loss procedures; and
- evidence retention without exposing secret material.

The observer's report must identify the tested candidate and deployment without
placing personal data, key bytes, device serials, or sensitive facility details
in the public repository.

## External deliverables and blocking effect

| External deliverable | Provider | What it supports | Missing evidence blocks |
| --- | --- | --- | --- |
| Independent security-review report and retest | Independent security reviewer | Application and composition assurance | Production security approval |
| RFC 3161 timestamp token and validation chain | Qualified/approved TSA | Independent existence-before-time claim | Trusted-time claim |
| Witnessed checkpoint or transparency proof | Independent witness/log | Stronger rollback and equivocation evidence | Externally witnessed history claim |
| Algorithm validation references | CAVP/ACVP process and laboratory | Tested algorithm implementation | Approved-algorithm listing on a new module certificate |
| FIPS 140-3 certificate and security policy | Accredited laboratory plus CMVP | Validated cryptographic-module claim | FIPS validated-module claim |
| Deployment compliance assessment | Authorized assessor/legal or customer authority | Framework-specific approval | Regulated or contractual compliance claim |
| Independent drill report, when required | Independent observer/auditor | Custody and recovery assurance | Operational approval under the applicable policy |

## How to engage external parties

Provide each party with:

- the exact candidate commit, version, and dependency lockfile;
- architecture, threat model, format specifications, and risk register;
- cryptographic inventory and proposed module boundary;
- deterministic vectors and negative tests;
- SBOM, reproducible-build, and provenance evidence;
- catalog/checkpoint specification and trust assumptions;
- custody, recovery, rotation, and incident procedures;
- known limitations and unresolved findings; and
- the precise claims the project hopes to make.

Ask for written confirmation of scope, independence, qualifications or
accreditation, deliverables, retest terms, certificate ownership, publication
rights, confidentiality, schedule, fees, and change/revalidation consequences.

## External completion definition

The external assurance work is complete only for the exact candidate and
deployment when:

- independent review has no unresolved Critical or High finding;
- remediations have independent retest evidence;
- trusted-time claims have verifiable TSA evidence, when such claims are made;
- rollback claims are tied to independently retained checkpoints or witnesses;
- validated-module claims cite an active certificate and follow its security
  policy and caveats;
- compliance claims cite a written deployment-specific determination;
- operational approval includes required independent drill evidence; and
- every public claim is narrower than or equal to the collected evidence.

External evidence can expire or become inapplicable after code, dependency,
module, operating-environment, policy, or deployment changes. Every release
must perform impact analysis before reusing prior evidence.
