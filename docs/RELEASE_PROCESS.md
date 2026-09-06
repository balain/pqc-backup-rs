# Release process

This process produces the independently verifiable artifacts required by
Phase 4. The unsigned `PQBACK02` envelope remains frozen; version 0.0.5 adds
the separately specified optional `PQSIG001` archive-provenance extension.

## Release gates

Before tagging:

1. Confirm the worktree is clean and based on the intended `main` commit.
2. Update the version in `Cargo.toml`, `Cargo.lock`, and `CHANGELOG.md`.
3. Run formatting, linting, locked tests, the dependency policy check, and the
   same-host release reproducibility check.
4. Review changes to format code against `docs/FORMAT_COMPATIBILITY.md` and the
   deterministic vectors.
5. Have a second maintainer review the commit and record approval outside the
   repository for any release intended for real recovery use.
6. Confirm that no secret material, archive, local path, or personal data is
   staged.

Required local checks:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
cargo deny check advisories bans licenses sources
./scripts/verify-release-build.sh "$(rustc -vV | sed -n 's/^host: //p')"
```

After creating the release commit and before tagging it, exercise recovery-kit
creation against that commit:

```bash
PATH="$HOME/.cargo/bin:$PATH" \
  ./scripts/build-recovery-kit.sh vX.Y.Z /tmp/pqbackup-release-check HEAD
```

The optional `SOURCE_REF` is for local pre-tag validation only. The automated
release omits it and therefore requires the release tag to identify `HEAD`.

## Commit and tag

Create one release commit describing the completed phase. Prefer a signed,
annotated tag when the maintainer has an approved signing key:

```bash
git add --all
git commit -m "Complete Phase N ..."
git tag -s vX.Y.Z -m "pqbackup vX.Y.Z"
```

If no approved signing key exists, an annotated tag may be used only for an
experimental release:

```bash
git tag -a vX.Y.Z -m "pqbackup vX.Y.Z"
```

Record that exception in the release notes. GitHub Actions provenance signs
the resulting assets, but it is not a substitute for a maintainer-signed source
tag. Do not generate or commit an ad hoc private signing key.

Push the commit and tag explicitly:

```bash
git push gh main
git push gh vX.Y.Z
```

## Automated release

The tag workflow uses exact revisions for every GitHub Action and exact
versions for the Rust toolchain, fuzz tool, dependency-policy tool, and SBOM
generator. It performs:

- locked build, tests, formatting, and warning-free linting;
- advisory, license, duplicate-version policy, wildcard, and source checks;
- pinned-nightly fuzz smoke campaigns for every parser target;
- two clean byte-for-byte release builds per supported target;
- native builds for Linux x86-64, Intel macOS, and Apple-silicon macOS;
- CycloneDX 1.5 SBOM generation;
- vendoring and a release test with Cargo in offline mode;
- deterministic source/recovery archives where GNU tar supports normalized
  metadata;
- SHA-256 manifests and a Sigstore/GitHub Actions provenance attestation;
- publication of all assets as a GitHub Release.

The recovery-kit script refuses a tag that does not identify `HEAD` or whose
version differs from `Cargo.toml`.

## Verify the published release

Two people should independently download and verify the release from clean
directories:

```bash
gh release download vX.Y.Z -R OWNER/REPOSITORY
shasum -a 256 -c SHA256SUMS
gh attestation verify \
  pqbackup-vX.Y.Z-recovery-kit.tar.gz \
  -R OWNER/REPOSITORY \
  --bundle pqbackup-vX.Y.Z-provenance.sigstore.json
```

Each verifier must also extract the kit, validate `MANIFEST.sha256`, restore the
known-good vector, and record the expected plaintext hash. At least one verifier
must perform the offline build in `docs/RECOVERY_RUNBOOK.md` before declaring
the Phase 4 operational gate complete.

## Preservation and incident handling

Copy the recovery kit, checksum manifest, detached provenance bundle, and
trusted-root file to at least two independently controlled locations. Apply the
schedule in `docs/RECOVERY_RUNBOOK.md`.

Do not delete or replace a release asset after publication. If any digest,
provenance, test, or build check fails, stop distribution, preserve evidence,
publish a security notice, and issue a new version after correction. Never
silently move an existing tag.
