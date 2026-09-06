# Parser fuzzing

Phase 2 includes three `cargo-fuzz` targets that call the same parsers used by
the CLI:

- `decode-header` exercises the `PQBACK02` header decoder;
- `decode-root-key` exercises the `PQROOT02` key decoder;
- `frame-traversal` exercises bounded frame-header and ciphertext traversal.

Install a Rust nightly toolchain and `cargo-fuzz`, then run:

```bash
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked
cargo +nightly fuzz run decode-header
cargo +nightly fuzz run decode-root-key
cargo +nightly fuzz run frame-traversal
```

For a finite local smoke run, add `-- -runs=1000`. CI runs that smoke campaign
for every target. Longer security campaigns should set an explicit time or run
budget, retain interesting corpus entries, and investigate every crash, hang,
or excessive-memory finding before release.

Generated corpus, artifacts, and fuzz build output are ignored by Git. A crash
artifact must be copied into a regression test before it is discarded.
