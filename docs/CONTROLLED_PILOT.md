# Phase 6 controlled-pilot procedure and evidence

## Automated pilot result

On 2026-09-06, the 0.0.6 candidate passed the disposable automated pilot in
`scripts/run-controlled-pilot.sh`. The script creates non-critical content and
separate temporary directories representing online work, ML-KEM custody, root
custody, signing custody, verification, two storage locations, and clean
recovery. It removes the complete temporary environment on exit.

The observed run reported `result=PASS` and elapsed time below the script's
one-second clock resolution. That time is useful only as a regression signal;
it is not a realistic recovery-time measurement.

| Scenario | Expected result | Observed |
| --- | --- | --- |
| Seal and separately sign | Signed archive created | Pass |
| Inspect encrypted filename | Plaintext filename absent | Pass |
| Provenance/content verification and clean restore | Exact plaintext comparison | Pass |
| Archive copied without keys | Restore fails | Pass |
| Truncated signed archive | Provenance and content checks fail | Pass |
| Lost ML-KEM copy | Verification fails | Pass |
| Lost root-key copy | Verification fails | Pass |
| Same root ID with wrong epoch | Verification fails | Pass |
| Revoked/compromised signer | Provenance verification fails | Pass |
| Substitute public key with same ID/epoch | Provenance verification fails | Pass |

Run it after building:

```bash
cargo build --locked
./scripts/run-controlled-pilot.sh target/debug/pqbackup
```

CI also performs a fresh locked offline build into a new target directory and
runs the pilot using that binary.

## Evidence boundaries

The automated pilot simulates separation with directories on one host. It does
not prove independent physical custody, resistance to host compromise, a human
operator's ability to follow the runbooks, media durability, or recovery on a
future platform. It also does not provide an external rollback catalog.

Therefore this result satisfies an engineering regression gate only. The Phase
6 independent-custody and clean-room exit criteria remain pending.

## Required real pilot

Use non-critical data that is independently recoverable. Assign different
custodians for at least two ML-KEM seed copies, two root-key copies, the signer,
the signer policy, and recovery-kit copies. No custodian should silently combine
the two recovery secret classes outside the supervised recovery window.

Record and test:

1. normal seal, transfer, provenance verification, and content verification;
2. restore on a clean, network-isolated system from retained release material;
3. restoration using each independent custody-copy combination;
4. an archive-only theft tabletop;
5. corrupted archive and corrupted removable-media copies;
6. one unavailable ML-KEM seed copy and one unavailable root-key copy;
7. wrong ID/epoch selection and inventory correction;
8. signing-key compromise, policy revocation, and replacement epoch;
9. source rebuild plus published-binary recovery; and
10. replay/rollback handling in the deployment's external catalog, if required.

## Drill evidence form

Do not commit personal names, secret paths, device serials, key bytes, archive
contents, or sensitive facility details. Retain sensitive evidence in the
deployment's controlled record system.

```text
Pilot identifier:
Candidate commit/tag and verified hashes:
Deployment class and non-critical data description:
Custodian roles (record identities externally):
Clean recovery environment description:
Scenarios completed and timestamps:
Restore elapsed time:
Operator errors and corrections:
Documentation gaps:
Unexpected results/incidents:
Evidence storage reference:
Independent observer approval:
Residual-risk owner decision:
```

A failed scenario blocks production consideration until its cause is resolved,
covered by a regression where applicable, and repeated successfully.
