# Security notes

> **Status:** Experimental and unaudited. This package must not be the sole
> protection for irreplaceable, regulated, or high-value data.

The authoritative scope and operating boundaries are documented in
[`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) and
[`docs/SUPPORTED_LIMITS.md`](docs/SUPPORTED_LIMITS.md).

## Threat model

`pqbackup` is designed for this principal scenario:

> An attacker obtains copies of encrypted backups today and retains them for
> future cryptanalysis, including future quantum attacks.

The design specifically avoids making long-term confidentiality depend solely
on a public-key primitive.

## Required secret separation

The strongest intended deployment keeps these independent:

1. ML-KEM-1024 secret seed (64 bytes)
2. archive root secret (32 bytes)

A stolen `.pqbk` archive contains the ML-KEM ciphertext but neither recovery
secret.

## Root-key rotation metadata

`PQBACK02` archives carry a stable 128-bit root-key ID and a caller-selected
rotation epoch. `keygen-root` records both with the 32-byte root secret in a
`PQROOT02` key file. The values are not secrets, but they are authenticated as
part of the encrypted DEK and filename metadata. A matching root-key file is
therefore required for recovery.

This metadata bounds key-custody blast radius operationally: rotate to a new
root key and epoch on the schedule appropriate for the archive's sensitivity.
The original filename is encrypted in `PQBACK02`; archive length remains
visible to support streaming recovery and integrity checks.

If a future attacker breaks ML-KEM but never acquires the root secret, the
derived KEK should remain unavailable.

## What this does not solve

- endpoint compromise while both secrets are mounted;
- malware reading the plaintext before encryption or after restore;
- weak physical custody;
- loss of all copies of a recovery secret;
- unreviewed cryptographic implementation defects;
- coerced disclosure;
- side channels outside the libraries and operating system.

## Secret backup policy

For every recovery secret, maintain at least two controlled copies. Avoid a
single device as the only copy.

A reasonable small-system layout:

```text
ML-KEM seed:
  copy A -> locked removable medium
  copy B -> separate secure location

root secret:
  copy A -> different locked removable medium
  copy B -> separate secure location
```

Do not store both secret classes in the same password manager, USB device,
cloud folder, or backup archive if your goal is independent failure domains.

The combined `keygen` command has been removed. Generate the two secret classes
independently with `keygen-kem` and `keygen-root` at their intended custody
locations. Demo mode intentionally co-locates disposable keys and is never an
acceptable production key layout.
