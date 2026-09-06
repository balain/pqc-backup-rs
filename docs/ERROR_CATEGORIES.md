# Decoder error categories

Exact CLI messages are diagnostics and are not a stable API. Implementations and automation should reason about these categories.

| Category | Meaning | Plaintext-output rule |
| --- | --- | --- |
| Invalid archive format | Magic, outer framing, or structure is not a supported archive | No completed output |
| Unsupported version | Recognized family with an unsupported version | No completed output |
| Unsupported algorithm | Algorithm ID or required parameter set is unknown | No completed output |
| Invalid structural field | Length, chunk size, flags, encoding, or extra bytes violate the specification | No completed output |
| Root-key metadata mismatch | Supplied root-key ID/epoch differs from visible archive routing data | No completed output |
| Key material invalid | Key file has wrong format, length, or encoding | No completed output |
| Authentication failed | Filename, wrapped DEK, or chunk did not authenticate | Temporary output removed |
| Chunk sequence failed | Index, finality, count, or total length is inconsistent | Temporary output removed |
| Archive truncated | Required header/frame bytes or final frame are missing | Temporary output removed |
| Trailing data | Bytes follow the authenticated final frame | Temporary output removed |
| Unsafe filename | Decrypted filename is not an allowed single component | No completed output |
| Output conflict | Destination already exists or cannot be created safely | Existing destination unchanged |
| Local I/O failure | Read, write, sync, permission, or rename failed | Existing destination unchanged; temporary cleanup attempted |

## Disclosure policy

Authentication-related failures SHOULD remain coarse in remote or multi-user contexts. The current CLI is local and may distinguish the filename, DEK-wrap, and chunk stage for diagnosis, but callers must not treat those distinctions as proof of key validity.

A failed operation MUST NOT rename a partial plaintext file into the requested destination. Cleanup failure may leave a hidden temporary file in the destination directory; operators should protect that directory as plaintext-bearing storage.

