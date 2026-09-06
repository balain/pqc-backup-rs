#!/bin/sh
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "usage: $0 VERSION OUTPUT_DIR [SOURCE_REF]" >&2
    exit 2
fi

version=$1
output_dir=$2
case "$version" in
    v[0-9]*.[0-9]*.[0-9]*) ;;
    *)
        echo "VERSION must look like vX.Y.Z" >&2
        exit 2
        ;;
esac

repo_root=$(git rev-parse --show-toplevel)
source_ref=${3:-$version}
commit=$(git -C "$repo_root" rev-parse "$source_ref^{commit}")
if [ "$#" -eq 2 ]; then
    head_commit=$(git -C "$repo_root" rev-parse HEAD)
    if [ "$commit" != "$head_commit" ]; then
        echo "tag $version does not identify the checked-out commit" >&2
        exit 1
    fi
fi

package_version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$repo_root/Cargo.toml" | head -n 1)
if [ "v$package_version" != "$version" ]; then
    echo "Cargo package version $package_version does not match tag $version" >&2
    exit 1
fi

mkdir -p "$output_dir"
output_dir=$(cd "$output_dir" && pwd)
stage=$(mktemp -d "${TMPDIR:-/tmp}/pqbackup-recovery.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM

source_root="$stage/pqbackup-$version"
kit_root="$stage/pqbackup-$version-recovery-kit"
source_archive="$output_dir/pqbackup-$version-source.tar.gz"
sbom="$output_dir/pqbackup-$version.cdx.json"
release_manifest="$output_dir/pqbackup-$version-release-manifest.txt"
recovery_archive="$output_dir/pqbackup-$version-recovery-kit.tar.gz"

mkdir -p "$source_root" "$kit_root/artifacts"
git -C "$repo_root" archive --format=tar.gz --prefix="pqbackup-$version/" "$source_ref" > "$source_archive"
git -C "$repo_root" archive "$source_ref" | tar -xf - -C "$source_root"

mkdir -p "$source_root/.cargo"
(
    cd "$source_root"
    cargo vendor --locked --versioned-dirs vendor > .cargo/config.toml
)

source_date_epoch=$(git -C "$repo_root" log -1 --format=%ct "$source_ref")
(
    cd "$source_root"
    SOURCE_DATE_EPOCH="$source_date_epoch" cargo cyclonedx \
        --format json \
        --spec-version 1.5 \
        --all \
        --target all \
        --override-filename "pqbackup-$version.cdx"
)
mv "$source_root/pqbackup-$version.cdx.json" "$sbom"

# Prove that the vendored tree is sufficient without consulting a registry.
(
    cd "$source_root"
    CARGO_HOME="$stage/offline-cargo-home" \
        CARGO_TARGET_DIR="$stage/offline-target" \
        cargo test --release --locked --offline
)

{
    echo "pqbackup release manifest v1"
    echo "version=$version"
    echo "commit=$commit"
    echo "source_date_epoch=$source_date_epoch"
    echo "rustc=$(rustc --version)"
    echo "cargo=$(cargo --version)"
    echo "cargo_lock_sha256=$(shasum -a 256 "$repo_root/Cargo.lock" | awk '{print $1}')"
    echo "archive_format=PQBACK02"
    echo "root_key_format=PQROOT02"
    echo "inventory_format=PQINVENTORY01"
    echo "provenance_format=PQSIG001"
    echo "signing_secret_format=PQSIGN01"
    echo "signing_public_format=PQPUBS01"
    echo "signer_policy_format=PQSIGNERS01"
    echo "sbom_format=CycloneDX-1.5-JSON"
    echo "provenance=GitHub-Actions-artifact-attestation"
} > "$release_manifest"

cp "$source_archive" "$kit_root/artifacts/"
cp "$sbom" "$kit_root/artifacts/"
cp "$release_manifest" "$kit_root/RELEASE-MANIFEST.txt"
cp "$source_root/docs/RECOVERY_RUNBOOK.md" "$kit_root/RECOVERY-RUNBOOK.md"
mv "$source_root" "$kit_root/source"

for asset in "$output_dir"/pqbackup-"$version"-*.tar.gz; do
    [ -f "$asset" ] || continue
    case "$asset" in
        *-source.tar.gz|*-recovery-kit.tar.gz) continue ;;
    esac
    cp "$asset" "$kit_root/artifacts/"
done

for trust_root in "$output_dir"/pqbackup-"$version"-trusted-root.jsonl; do
    [ -f "$trust_root" ] || continue
    cp "$trust_root" "$kit_root/artifacts/"
done

(
    cd "$kit_root"
    find . -type f ! -name MANIFEST.sha256 -print | LC_ALL=C sort | \
        while IFS= read -r file; do shasum -a 256 "$file"; done > MANIFEST.sha256
)

if tar --version 2>/dev/null | grep -q 'GNU tar'; then
    tar --sort=name \
        --mtime="@$source_date_epoch" \
        --owner=0 \
        --group=0 \
        --numeric-owner \
        -C "$stage" \
        -czf "$recovery_archive" \
        "$(basename "$kit_root")"
else
    tar -C "$stage" -czf "$recovery_archive" "$(basename "$kit_root")"
fi

(
    cd "$output_dir"
    find . -maxdepth 1 -type f ! -name SHA256SUMS -print | LC_ALL=C sort | \
        while IFS= read -r file; do shasum -a 256 "$file"; done > SHA256SUMS
)

echo "recovery kit created: $recovery_archive"
