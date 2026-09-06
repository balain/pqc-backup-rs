# Format compatibility policy

## Stable formats

The unsigned `PQBACK02` archive encoding and `PQROOT02` key encoding version 1
are frozen by their specifications and deterministic vectors. `pqbackup` 0.0.5
adds the rigorously specified optional `PQSIG001` trailer without changing any
unsigned-envelope byte. Signed archives require a 0.0.5-or-later decoder;
pre-0.0.5 decoders reject them as trailing data.

Within these versions, maintainers MAY:

- improve diagnostics without making exact text an API;
- reject inputs already invalid under the specification;
- fix a decoder that incorrectly rejects a valid specified archive;
- improve memory handling, performance, or platform integration without changing bytes;
- add commands that do not alter encoding semantics.
- append or omit exactly one `PQSIG001` extension as specified in
  [`PQBACK02_PROVENANCE_FORMAT.md`](./PQBACK02_PROVENANCE_FORMAT.md).

Maintainers MUST NOT silently change:

- field order, size, byte order, or encoding;
- algorithm or parameter-set meaning;
- domain-separation strings;
- KDF input order or lengths;
- nonce or AAD construction;
- filename rules;
- final-frame semantics;
- root-key ID/epoch meaning;
- required authentication or rejection behavior.

Any such change requires a new archive magic/version or root-key format version, new specifications, and new vectors.

## Decoder dispatch

The current decoder accepts only `PQBACK02` version 2, `PQROOT02` key version 1,
and optionally `PQSIG001` version 1. Unknown magic, version, algorithm ID,
extra header bytes, or non-canonical trailer bytes are rejected. Decoders must
dispatch on magic/version before interpreting version-specific fields; they
must not guess based on file length.

## Backward compatibility

Future releases that claim v2 compatibility must keep reading every valid
unsigned `PQBACK02` vector and real v2 archive. Releases claiming provenance
compatibility must also preserve the exact `PQSIG001` signed representation.
The deterministic vector test is a mandatory release gate.

Adding a future encoder version does not justify removing the v2 decoder while retained archives depend on it. If a vulnerability makes v2 decoding unsafe, releases must document the risk and provide a controlled migration path rather than silently changing v2 semantics.

## Migration

Archive migration is decrypt–verify–reseal:

1. authenticate and restore with the old decoder and matching keys;
2. validate the recovered application-level content;
3. seal under the new format and intended key epoch;
4. verify the new archive;
5. retain the old archive and decoder until policy authorizes retirement.

Ciphertext-only transformation is not supported because the filename, wrapped DEK, and chunk AAD are version-bound.

Root-key migration requires preserving the old key until all dependent archives are migrated. A new key-format version must not overwrite old key material in place.

## Release requirements

A release that changes format-related code must:

- run deterministic vector tests;
- identify whether bytes changed intentionally;
- use a new format version for intentional semantic changes;
- update specifications, negative vectors, compatibility notes, and recovery instructions;
- preserve a known-good decoder for every supported retained format.
