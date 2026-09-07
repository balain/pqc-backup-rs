# Secret memory and filesystem handling

**Applies to:** 0.1.3, security hardening Phase 2  
**Scope:** owner-controlled engineering; no independent validation claimed

## Secret lifetime inventory

The implementation uses `Zeroizing` containers for application-owned secret
buffers. This inventory distinguishes those containers from dependency internals
and operating-system copies. A passing test cannot prove universal memory erasure.

| Material | Application ownership and cleanup | Remaining boundary |
| --- | --- | --- |
| ML-KEM seed | Bounded secret-file buffer and decoded array are zeroizing; exported key-generation seed is wrapped immediately | Library return/move temporaries and registers are not exhaustively controlled |
| ML-KEM decapsulation key | Locked `ml-kem` 0.3.2 has a zeroizing `Drop` with the enabled feature; dropped after decapsulation | Dependency-internal intermediate values require separate analysis |
| ML-KEM shared secret | Immediately wrapped in `Zeroizing`, dropped after KEK derivation | The library's return-value construction may make transient copies |
| Root secret | `RootKey.secret`, serialized key bytes, and bounded read buffer are zeroizing; provider dropped after derivation | Reading a file also exposes its bytes to the kernel page cache |
| Signing seed/key | Serialized and decoded seeds are protected; temporary ML-DSA seed is explicitly erased; locked `ml-dsa` 0.1.1 erases signing/expanded-key state with the enabled feature | No claim covers all dependency intermediates or compiler copies |
| KDF input/output | Concatenated input and returned KEK are zeroizing; application KEK and wrapping ciphers are dropped after use | Locked `hkdf` 0.13.0 does not expose an application-controlled zeroizing HKDF-state interface; internal HMAC/KDF state remains a limitation |
| DEK | Random, unwrapped, and decoded DEK buffers are zeroizing; dropped after construction of the payload cipher | Payload cipher must remain usable for the complete stream |
| AES-GCM state | Enabled `aes-gcm` 0.11.1 zeroize feature forwards to AES and GHASH zeroization | Does not imply operating-system or arbitrary temporary-memory erasure |
| Plaintext chunks | Seal uses a zeroizing chunk buffer and direct file reads; restore uses zeroizing decrypted chunks and direct file writes | Kernel buffers, snapshots, swap, and destination storage are outside these guards |
| Original filename | Decrypted bytes and retained UTF-8 string are zeroizing; UTF-8 errors do not own an unprotected copied buffer | Original CLI paths and destination `PathBuf` values remain ordinary OS-facing path data |

Sealing no longer puts plaintext into an additional `BufReader` buffer, and
restore no longer puts it into an additional `BufWriter` buffer. Ciphertext
buffering remains. Secret serialization allocates its full known capacity;
bounded reads allocate their limit once, avoiding secret-bearing reallocations.

Do not add secret-bearing debug output. Root keys have no derived `Debug`
implementation. Errors may identify file paths and policy metadata, but must not
contain key bytes, plaintext, or PINs.

## Core dumps and memory locking

Core-dump suppression and page locking were assessed as optional defense in
depth. No new process-wide memory-locking or dump-control feature is claimed.

- Operators can launch the program from a shell with `ulimit -c 0` to disable
  ordinary core files through the inherited resource limit. This does not
  control every platform crash collector, debugger, or privileged process.
- Locking only application key buffers would leave library state and temporary
  copies uncovered. Locking an entire process can exceed platform limits or
  require extra privileges, and must not be silently presented as complete
  protection. A future supported mode needs platform tests and explicit failure
  reporting before it is advertised.
- Use an encrypted local volume and appropriate swap/hibernation controls for
  recovery. Memory erasure does not defend against a compromised live host.

## Strict material-file reads

Key, inventory, and signer-policy files are opened once and validated from the
open descriptor. On supported Unix systems, `O_NOFOLLOW` rejects a final-component
symlink and `O_NONBLOCK` prevents a FIFO open from waiting indefinitely. Non-regular
files are rejected before reading. Earlier directory components may still be
symlinks; the complete parent-directory chain must be trusted.

Secret files must be owned by the current effective user and grant no Unix
group/other permissions. Modes `0600` and `0400` are supported. Public keys,
inventory, and policy files do not receive the secret-mode restriction, although
their integrity still depends on trusted custody and directory permissions.

There is no automatic chmod, ownership change, symlink resolution, or permissive
fallback. For an intentionally linked key, select the verified real file path.
For an imported permissive secret, inspect custody and access first, then restrict
the intended file, for example:

```sh
chmod 600 /trusted/custody/archive.root.key
```

Mode/UID checks are not an ACL audit. Inspect extended ACLs separately (for example,
`ls -le` on macOS or `getfacl` where available on Linux); remove unintended grants
through the custody procedure. Require trusted, non-adversary-writable ancestors,
mounts, and output directories. These checks do not defend against an attacker
who can replace parent directories or change permissions after validation.

Fixed-size readers consume at most the expected size plus one byte; policy and
inventory readers consume at most their configured ceiling plus one byte. Growth
after metadata inspection cannot bypass the read cap. Unknown sizes, truncated
keys, excess bytes, and invalid text are rejected. File metadata is not treated
as a stable content snapshot.

## Staging and durability

New key files are written completely to exclusively created same-directory
temporary files and synchronized before publication. A cleanup guard is acquired
only after successful creation, so a failed creation does not authorize removing
somebody else's file. New key directories are mode `0700` on Unix, with creation
of each directory entry synchronized. Existing directories are not chmodded.

Hard-link publication preserves no-overwrite behavior. The parent directory is
synchronized after publication and again after temporary-name removal. Policy
replacement uses rename followed by parent-directory synchronization. Successful
best-effort cleanup also attempts parent-directory synchronization.

If publication or replacement succeeds but later synchronization or cleanup fails,
the command returns an error explicitly stating that the output was published or
replaced. The destination may already contain a complete result. Inspect and
verify it before retrying; do not assume every nonzero exit means no output exists.

Both public and secret key files are staged before either is published. The secret
is published first. There is no portable atomic two-file transaction: a crash or
second-publication failure can leave a complete secret without its public file.
The error identifies the retained secret and possible public output. No published
recovery secret or pre-existing file is deleted as rollback. Keep the incomplete
pair isolated; generate a fresh pair under a new name if restarting provisioning.
Do not seal archives with an unverified or incomplete pair.

These are filesystem synchronization requests, not a guarantee against faulty
storage hardware, all macOS power-loss behaviors, network mounts, or unsupported
filesystems. Preserve independent backups and validate restored application data.

## Abandoned plaintext temporary files

Normal failure cleans up owned temporary files when the OS permits. `SIGKILL`,
power loss, and failed removal can leave a mode-`0600` plaintext prefix. Such a
file is not a verified complete restore and must never be promoted by hand.

Manual inspection and cleanup procedure:

1. Stop relevant restore jobs and confirm no process still uses the candidate;
   inspect open handles with the available OS tools. If active-operation state
   is uncertain, leave the file in place until it is established.
2. Identify the exact output directory and interrupted operation. The temporary
   naming pattern is only a hint, never authorization for deletion.
3. Inspect the exact candidate without following symlinks: require an owned
   regular file at the expected location. Review parent-directory trust,
   permissions/ACLs, and whether another operation could still access it.
4. Delete only the individually verified candidate. Do not use a blanket wildcard
   cleanup command. Use an OS/filesystem-aware procedure if directory-entry
   durability after manual cleanup is required.
5. Restart recovery from the archive into a new destination and perform all
   cryptographic and application checks. Keep secret media under normal custody.

Deletion is not secure erasure of SSD blocks, snapshots, backups, or page-cache
copies. An encrypted restore volume limits exposure of remnants at rest.

## Internal evidence

Phase 2 adds tests for bounded reads and growth, secret ownership/modes,
symlinks/FIFOs/devices, partial writes, flush/sync/publication failures, retained
secret pairs, no-overwrite behavior, and abrupt subprocess termination.
Fault injection exists only in the unit-test binary and is scoped to the current
test thread. It cannot be enabled by production environment variables.

The termination test kills a disposable test subprocess after writing a private
temporary plaintext file. It confirms that the destination was not published,
the private remnant exists, and explicit cleanup is required. It is not a
physical power-loss or storage-controller test.
