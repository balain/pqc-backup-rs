#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 TARGET [OUTPUT_BINARY]" >&2
    exit 2
fi

target=$1
output=${2:-}
repo_root=$(git rev-parse --show-toplevel)
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/pqbackup-repro.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

source_date_epoch=$(git -C "$repo_root" log -1 --format=%ct)
export SOURCE_DATE_EPOCH="$source_date_epoch"
export CARGO_INCREMENTAL=0
export RUSTFLAGS="${RUSTFLAGS:--Dwarnings}"

for build_dir in first second; do
    cargo build \
        --manifest-path "$repo_root/Cargo.toml" \
        --release \
        --locked \
        --target "$target" \
        --target-dir "$work_dir/$build_dir"
done

first_binary="$work_dir/first/$target/release/pqbackup"
second_binary="$work_dir/second/$target/release/pqbackup"

if ! cmp -s "$first_binary" "$second_binary"; then
    echo "release binaries differ across clean same-host builds" >&2
    exit 1
fi

if [ -n "$output" ]; then
    mkdir -p "$(dirname "$output")"
    cp "$first_binary" "$output"
    chmod 0755 "$output"
fi

echo "same-host reproducibility check passed for $target"
shasum -a 256 "$first_binary"
