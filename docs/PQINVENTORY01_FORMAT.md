# PQINVENTORY01 root-key inventory format

**Status:** version 1 operational metadata format
**Encoding:** UTF-8 TOML
**Maximum file size:** 1 MiB

`PQINVENTORY01` maps `PQROOT02` identifiers and epochs to human-readable
custody locations. It MUST NOT contain secret bytes, passwords, PINs, recovery
phrases, unlock instructions, or copies of key files.

## Structure

```toml
format = "PQINVENTORY01"

[[root_keys]]
id = "00112233445566778899aabbccddeeff"
epoch = 2026
status = "active"
label = "Annual archive root"
custody = ["Primary sealed offline copy", "Offsite sealed recovery copy"]
```

The top-level table has exactly these fields:

| Field | Required | Meaning |
| --- | --- | --- |
| `format` | Yes | Must equal `PQINVENTORY01` |
| `root_keys` | No | Array of zero or more root-key records |

Each root-key record has exactly these fields:

| Field | Required | Validation |
| --- | --- | --- |
| `id` | Yes | Canonical lowercase 32-character hexadecimal root-key ID |
| `epoch` | Yes | Unsigned 32-bit epoch |
| `status` | Yes | `active`, `retired`, `compromised`, or `destroyed` |
| `label` | No | Non-empty single line, at most 200 UTF-8 bytes |
| `custody` | Yes | One or more unique non-empty single lines, each at most 1024 UTF-8 bytes |

The pair `(id, epoch)` MUST be unique. Unknown fields, duplicate identities,
non-canonical IDs, control or bidirectional-formatting characters, and
unsupported status values are rejected.

## Lifecycle status

- `active`: approved for creating new archives and recovery.
- `retired`: retained for recovery but not approved for new archives.
- `compromised`: suspected or confirmed exposure; follow the compromise
  procedure and migrate affected archives.
- `destroyed`: custody records remain for history, but recovery material is
  intentionally no longer available.

Changing status preserves the record. Do not delete historical records merely
because an epoch is retired, compromised, or destroyed.

## Security and update behavior

The inventory is not cryptographically authenticated in this phase. Treat it
as untrusted routing information until the selected key authenticates an
archive. Maintain controlled backups and compare it with independent custody
records.

The CLI creates the file with mode `0600` on supported Unix platforms. Updates
are written to a restrictive same-directory temporary file, synchronized, and
atomically replaced. A 1 MiB input ceiling bounds parsing and memory use.

Custody descriptions may reveal security arrangements. Protect the inventory
even though it contains no recovery secrets.
