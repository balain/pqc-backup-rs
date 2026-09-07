#!/bin/sh
set -eu

binary=${1:-target/release/pqbackup}
case "$binary" in
  /*) ;;
  *) binary=$(pwd)/$binary ;;
esac

if [ ! -x "$binary" ]; then
  echo "pilot error: executable not found: $binary" >&2
  exit 2
fi

pilot_dir=$(mktemp -d "${TMPDIR:-/tmp}/pqbackup-pilot.XXXXXX")
trap 'rm -rf "$pilot_dir"' EXIT HUP INT TERM
started=$(date +%s)

online="$pilot_dir/online"
kem_custody="$pilot_dir/kem-custody"
root_custody="$pilot_dir/root-custody"
signing_custody="$pilot_dir/signing-custody"
verifier="$pilot_dir/verifier"
storage_a="$pilot_dir/storage-a"
storage_b="$pilot_dir/storage-b"
recovery="$pilot_dir/clean-recovery"
mkdir -p "$online" "$kem_custody" "$root_custody" "$signing_custody" \
  "$verifier" "$storage_a" "$storage_b" "$recovery"

expect_failure() {
  scenario=$1
  shift
  if "$@" >"$pilot_dir/$scenario.stdout" 2>"$pilot_dir/$scenario.stderr"; then
    echo "pilot error: $scenario unexpectedly succeeded" >&2
    exit 1
  fi
  echo "scenario.$scenario=PASS"
}

root_id=102132435465768798a9bacbdcedfe0f
signer_id=00112233445566778899aabbccddeeff
plaintext_name=phase6-private-name.txt
plaintext="$online/$plaintext_name"
unsigned="$storage_a/pilot-unsigned.pqbk"
signed="$storage_b/pilot-signed.pqbk"
policy="$verifier/signer-policy.toml"

printf '%s\n' 'Non-critical Phase 6 controlled-pilot content.' >"$plaintext"

"$binary" keygen-kem --out-dir "$kem_custody" --name pilot >/dev/null
"$binary" keygen-root \
  --output "$root_custody/pilot.root.key" \
  --root-key-id "$root_id" \
  --root-key-epoch 6 >/dev/null
"$binary" keygen-signing \
  --out-dir "$signing_custody" \
  --name pilot-signer \
  --signer-key-id "$signer_id" \
  --signer-key-epoch 6 >/dev/null
"$binary" signer-policy init "$policy" >/dev/null
"$binary" signer-policy add "$policy" \
  --public-key "$signing_custody/pilot-signer.mldsa87.pub" \
  --identity "Phase 6 controlled-pilot signer" >/dev/null

"$binary" seal "$plaintext" \
  --public-key "$kem_custody/pilot.mlkem1024.pub" \
  --root-secret "$root_custody/pilot.root.key" \
  --expect-root-key-id "$root_id" \
  --expect-root-key-epoch 6 \
  --output "$unsigned" >/dev/null
"$binary" sign "$unsigned" \
  --signing-key "$signing_custody/pilot-signer.mldsa87.seed" \
  --output "$signed" >/dev/null
echo "scenario.seal_and_sign=PASS"

"$binary" inspect "$signed" >"$pilot_dir/inspect.txt"
if grep -F "$plaintext_name" "$pilot_dir/inspect.txt" >/dev/null; then
  echo "pilot error: inspect disclosed the encrypted filename" >&2
  exit 1
fi
echo "scenario.inspect_redaction=PASS"

"$binary" provenance-verify "$signed" \
  --public-key "$signing_custody/pilot-signer.mldsa87.pub" \
  --policy "$policy" >/dev/null
"$binary" verify "$signed" \
  --secret-key "$kem_custody/pilot.mlkem1024.seed" \
  --root-secret "$root_custody/pilot.root.key" >/dev/null
"$binary" open "$signed" \
  --secret-key "$kem_custody/pilot.mlkem1024.seed" \
  --root-secret "$root_custody/pilot.root.key" \
  --output "$recovery/restored.txt" >/dev/null
cmp "$plaintext" "$recovery/restored.txt"
echo "scenario.clean_restore=PASS"

"$binary" verify "$signed" \
  --secret-key "$kem_custody/pilot.mlkem1024.seed" \
  --root-secret "$root_custody/pilot.root.key" \
  --require-provenance \
  --signer-public-key "$signing_custody/pilot-signer.mldsa87.pub" \
  --signer-policy "$policy" >/dev/null
"$binary" open "$signed" \
  --secret-key "$kem_custody/pilot.mlkem1024.seed" \
  --root-secret "$root_custody/pilot.root.key" \
  --require-provenance \
  --signer-public-key "$signing_custody/pilot-signer.mldsa87.pub" \
  --signer-policy "$policy" \
  --output "$recovery/required-provenance.txt" >/dev/null
cmp "$plaintext" "$recovery/required-provenance.txt"
echo "scenario.required_provenance_restore=PASS"
expect_failure unsigned_required_provenance "$binary" open "$unsigned" \
  --secret-key "$kem_custody/pilot.mlkem1024.seed" \
  --root-secret "$root_custody/pilot.root.key" \
  --require-provenance \
  --signer-public-key "$signing_custody/pilot-signer.mldsa87.pub" \
  --signer-policy "$policy" \
  --output "$recovery/must-not-exist.txt"
if [ -e "$recovery/must-not-exist.txt" ]; then
  echo "pilot error: unsigned required restore published plaintext" >&2
  exit 1
fi


cp "$signed" "$pilot_dir/stolen.pqbk"
expect_failure archive_theft "$binary" open "$pilot_dir/stolen.pqbk" \
  --secret-key "$pilot_dir/unavailable.mlkem1024.seed" \
  --root-secret "$pilot_dir/unavailable.root.key" \
  --output "$pilot_dir/stolen-plaintext"

archive_size=$(wc -c <"$signed" | tr -d ' ')
truncated_size=$((archive_size - 1))
dd if="$signed" of="$storage_a/corrupted.pqbk" bs=1 count="$truncated_size" 2>/dev/null
expect_failure corrupted_provenance "$binary" provenance-verify "$storage_a/corrupted.pqbk" \
  --public-key "$signing_custody/pilot-signer.mldsa87.pub" --policy "$policy"
expect_failure corrupted_recovery "$binary" verify "$storage_a/corrupted.pqbk" \
  --secret-key "$kem_custody/pilot.mlkem1024.seed" \
  --root-secret "$root_custody/pilot.root.key"

expect_failure lost_kem_copy "$binary" verify "$signed" \
  --secret-key "$pilot_dir/lost.mlkem1024.seed" \
  --root-secret "$root_custody/pilot.root.key"
expect_failure lost_root_copy "$binary" verify "$signed" \
  --secret-key "$kem_custody/pilot.mlkem1024.seed" \
  --root-secret "$pilot_dir/lost.root.key"

"$binary" keygen-root \
  --output "$root_custody/wrong-epoch.root.key" \
  --root-key-id "$root_id" \
  --root-key-epoch 7 >/dev/null
expect_failure wrong_root_epoch "$binary" verify "$signed" \
  --secret-key "$kem_custody/pilot.mlkem1024.seed" \
  --root-secret "$root_custody/wrong-epoch.root.key"

revoked_policy="$verifier/revoked-policy.toml"
cp "$policy" "$revoked_policy"
"$binary" signer-policy set-status "$revoked_policy" \
  --signer-key-id "$signer_id" --signer-key-epoch 6 --status revoked >/dev/null
expect_failure compromised_signer "$binary" provenance-verify "$signed" \
  --public-key "$signing_custody/pilot-signer.mldsa87.pub" --policy "$revoked_policy"

"$binary" keygen-signing \
  --out-dir "$pilot_dir/substitute" \
  --name substitute \
  --signer-key-id "$signer_id" \
  --signer-key-epoch 6 >/dev/null
expect_failure substituted_signer "$binary" provenance-verify "$signed" \
  --public-key "$pilot_dir/substitute/substitute.mldsa87.pub" --policy "$policy"

finished=$(date +%s)
echo "pilot_format=PQBACKUP_PILOT01"
echo "pilot_data=non-critical"
echo "custody_model=simulated-separated-directories"
echo "elapsed_seconds=$((finished - started))"
echo "result=PASS"
