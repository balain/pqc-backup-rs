# Recovery runbook

**Applies to:** `PQBACK02`, `PQROOT02`, `PQINVENTORY01`, and optional
`PQSIG001` provenance as shipped with `pqbackup` 0.0.5. This project remains
experimental and unaudited.

This runbook is for recovering data after the original development machine,
package registry, or normal build environment is unavailable. Keep a printed
copy with each controlled recovery-kit copy.

## Materials required

A real archive requires all of the following:

- the `.pqbk` archive;
- its matching 64-byte ML-KEM seed;
- the `PQROOT02` root-key file whose ID and epoch match the archive;
- a compatible `pqbackup` binary or the recovery kit needed to rebuild one.

When creator provenance must also be validated, recovery additionally requires
the matching `PQPUBS01` public key and an authenticated historical
`PQSIGNERS01` policy. Neither file can decrypt the archive.

The ML-KEM seed and root key must remain in separate custody. Do not place
either real secret in the recovery kit.

Each tagged release publishes a recovery-kit archive and detached Sigstore
provenance bundle. The kit contains:

- a complete source tree and `Cargo.lock`;
- the pinned Rust toolchain declaration;
- vendored dependency sources and Cargo's offline source configuration;
- format specifications, security documents, and CLI documentation;
- positive and negative test vectors, including public test-only keys;
- known-good binaries for supported 64-bit Linux and macOS targets;
- a CycloneDX SBOM, release manifest, and nested SHA-256 manifest;
- the trusted roots captured when the release was built.

The detached provenance bundle is distributed beside the kit because a file
cannot contain its own signature without changing the signed digest.

## Acquire and authenticate a release

On a networked staging system, download every asset for the selected release.
Replace `OWNER/REPOSITORY` with the repository shown on the release page.

First verify the release's SHA-256 manifest:

```bash
shasum -a 256 -c SHA256SUMS
```

Then verify the kit's build provenance. This checks that the downloaded bytes
match an attestation issued to this repository's release workflow:

```bash
gh attestation verify \
  pqbackup-vX.Y.Z-recovery-kit.tar.gz \
  -R OWNER/REPOSITORY \
  --bundle pqbackup-vX.Y.Z-provenance.sigstore.json
```

For later offline verification, preserve all of these together:

- `pqbackup-vX.Y.Z-recovery-kit.tar.gz`;
- `pqbackup-vX.Y.Z-provenance.sigstore.json`;
- `pqbackup-vX.Y.Z-trusted-root.jsonl`;
- `SHA256SUMS`.

On the offline recovery system, the provenance check is:

```bash
gh attestation verify \
  pqbackup-vX.Y.Z-recovery-kit.tar.gz \
  -R OWNER/REPOSITORY \
  --bundle pqbackup-vX.Y.Z-provenance.sigstore.json \
  --custom-trusted-root pqbackup-vX.Y.Z-trusted-root.jsonl
```

An attestation proves repository/workflow provenance and integrity. It does
not prove that the source is vulnerability-free or independently audited.

## Validate the recovery kit offline

Disconnect networking before this procedure. Extract the kit into a new empty
directory, enter its top-level directory, and verify every nested file:

```bash
tar -xzf pqbackup-vX.Y.Z-recovery-kit.tar.gz
cd pqbackup-vX.Y.Z-recovery-kit
shasum -a 256 -c MANIFEST.sha256
```

Use the included binary matching the recovery host and confirm it starts:

```bash
tar -xzf artifacts/pqbackup-vX.Y.Z-linux-x86_64.tar.gz
./pqbackup --version
./pqbackup --help
```

For Apple silicon use `macos-aarch64`; for Intel macOS use `macos-x86_64`.
Do not run a binary for a different architecture through an emulator for a
production recovery drill.

## Validate the known-good archive

The fixture secrets are public test data and must never be used for real
archives. Convert the hexadecimal fixtures in a temporary test directory:

```bash
mkdir vector-check
sed '/^#/d' source/test-vectors/one-chunk.pqbk.hex | \
  xxd -r -p > vector-check/one-chunk.pqbk
xxd -r -p source/test-vectors/mlkem-seed.hex \
  > vector-check/vector.mlkem1024.seed
sed '/^#/d' source/test-vectors/root-key.hex | \
  xxd -r -p > vector-check/vector.root.key
```

Verify and restore the vector:

```bash
./pqbackup verify vector-check/one-chunk.pqbk \
  --secret-key vector-check/vector.mlkem1024.seed \
  --root-secret vector-check/vector.root.key

./pqbackup open vector-check/one-chunk.pqbk \
  --secret-key vector-check/vector.mlkem1024.seed \
  --root-secret vector-check/vector.root.key \
  --output vector-check/recovered.txt

shasum -a 256 vector-check/recovered.txt
```

The expected plaintext digest is
`14d85f6e6cc62f0de86ca2a04d7ff5b1cdc7902891f4c603eda4eb88cfb52730`.
Delete the temporary public-vector files after the drill to avoid confusing
them with production recovery material.

## Rebuild without network access

The `source/vendor` directory and `source/.cargo/config.toml` redirect Cargo to
the preserved dependency sources. Install the exact Rust toolchain named in
`source/rust-toolchain.toml` before isolating the machine, then run:

```bash
cd source
cargo build --release --locked --offline
cargo test --release --locked --offline
```

Compare the rebuilt binary on the same operating system and architecture:

```bash
../../pqbackup --version
target/release/pqbackup --version
```

The release pipeline compares two clean same-host builds byte-for-byte. Rust
binaries are not claimed to be byte-identical across different operating
system images or architectures; verify provenance, tests, behavior, and the
documented source/lock/toolchain inputs together.

## Recover a real archive

1. Work on a hardened, offline machine with encrypted local storage and
   controlled swap/hibernation.
2. Make a read-only working copy of the archive. Do not test the only copy.
3. Run `inspect` and record the visible root-key and signer routing metadata.
   Treat it only as unauthenticated hints.
4. If provenance matters, retrieve the independently authenticated signer
   public key and historical policy, then run `provenance-verify`. Record that
   it does not establish creation time or newest-backup status.
5. Retrieve the matching root key and ML-KEM seed through their separate
   custody procedures.
6. Run `verify` before creating plaintext.
7. Run `open` to a new destination on a local filesystem. Existing files are
   never overwritten.
8. Validate the recovered application's own hashes or file structure.
9. Remove both secret media, record the drill, and handle plaintext according
   to the data policy. Secure deletion is not guaranteed on SSD, snapshots,
   copy-on-write, or backed-up storage.

## Scheduled preservation work

Assign named people in the external operations record; do not put personal
contact details in this repository.

| Activity | Minimum cadence | Evidence |
| --- | --- | --- |
| Hash every archive and recovery-kit copy | Quarterly | Dated checksum report and exceptions |
| Restore the public vector from each supported binary | Every release and annually | Command log and digest |
| Restore a representative real archive from each custody copy | Annually | Two-person drill record |
| Refresh removable media | Every five years or earlier per manufacturer guidance | New media identifiers and verified hashes |
| Review dependencies, standards, and cryptographic status | Every two years and after a material advisory | Review record and migration decision |
| Confirm owners, locations, and access procedures | Annually and after personnel changes | Approved custody inventory |
| Verify signer policy history and revocation distribution | Every policy change and annually | Authenticated policy snapshots and change record |

Migrate archives before a primitive, dependency, operating environment, or
storage medium leaves the organization's accepted risk boundary. Never destroy
the old key epoch or archive until the replacement has been independently
verified and its recovery drill has passed.
