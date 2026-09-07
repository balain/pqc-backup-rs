use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use hkdf::Hkdf;
use ml_dsa::{
    EncodedVerifyingKey, Keypair, MlDsa87, Seed as MlDsaSeed, Signature as MlDsaSignature,
    SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey,
    signature::{DigestSigner, DigestVerifier, digest::Update},
};
use ml_kem::{
    MlKem1024,
    kem::{Decapsulate, Encapsulate, Kem, KeyExport, TryKeyInit},
    ml_kem_1024::{DecapsulationKey, EncapsulationKey},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"PQBACK02";
const VERSION: u16 = 2;
const ROOT_MAGIC: &[u8; 8] = b"PQROOT02";
const ROOT_VERSION: u16 = 1;
const KEM_ID_MLKEM1024: u16 = 1;
const KDF_ID_HKDF_SHA384: u16 = 1;
const AEAD_ID_AES256GCM: u16 = 1;
const DEFAULT_CHUNK: u32 = 4 * 1024 * 1024;
const MAX_CHUNK: u32 = 16 * 1024 * 1024;
const MAX_HEADER_LEN: usize = 64 * 1024;
const MAX_PLAINTEXT_LEN: u64 = 1 << 40;
const MAX_DATA_CHUNKS: u64 = 1 << 20;
const GCM_TAG_LEN: usize = 16;
const MLKEM1024_CT_LEN: usize = 1568;
const MLKEM1024_PK_LEN: usize = 1568;
const MLKEM_SEED_LEN: usize = 64;
const ROOT_SECRET_LEN: usize = 32;
const DEK_LEN: usize = 32;
const ROOT_KEY_ID_LEN: usize = 16;
const MAX_FILENAME_LEN: usize = 4096;
const INVENTORY_FORMAT: &str = "PQINVENTORY01";
const MAX_INVENTORY_LEN: u64 = 1024 * 1024;
const MAX_INVENTORY_LABEL_LEN: usize = 200;
const MAX_CUSTODY_LOCATION_LEN: usize = 1024;
const SIGNING_SECRET_MAGIC: &[u8; 8] = b"PQSIGN01";
const SIGNING_PUBLIC_MAGIC: &[u8; 8] = b"PQPUBS01";
const SIGNING_KEY_VERSION: u16 = 1;
const SIGNATURE_ALG_MLDSA87: u16 = 1;
const SIGNER_KEY_ID_LEN: usize = 16;
const MLDSA_SEED_LEN: usize = 32;
const MLDSA87_PUBLIC_KEY_LEN: usize = 2592;
const MLDSA87_SIGNATURE_LEN: usize = 4627;
const PROVENANCE_MAGIC: &[u8; 8] = b"PQSIG001";
const PROVENANCE_VERSION: u16 = 1;
const PROVENANCE_STATEMENT_LEN: usize = 8 + 2 + 2 + SIGNER_KEY_ID_LEN + 4 + 8 + 4;
const PROVENANCE_DOMAIN: &[u8] = b"pqbackup/provenance/v1\0";
const SIGNER_POLICY_FORMAT: &str = "PQSIGNERS01";
const MAX_SIGNER_POLICY_LEN: u64 = 1024 * 1024;
const MAX_SIGNER_IDENTITY_LEN: usize = 300;

struct DecryptedArchive {
    header: Header,
    original_name: Zeroizing<String>,
    provenance: Option<ProvenanceTrailer>,
}

/// Observes only bytes consumed by the parser, not BufReader read-ahead.
/// Signature hashing stops at the envelope boundary; SHA-256 includes the trailer.
struct ArchiveReader<'a, R> {
    inner: R,
    signature_digest: Option<&'a mut dyn Update>,
    archive_digest: Sha256,
    archive_len: u64,
}

impl<'a, R: Read> ArchiveReader<'a, R> {
    fn new(inner: R, signature_digest: Option<&'a mut dyn Update>) -> Self {
        Self {
            inner,
            signature_digest,
            archive_digest: Sha256::new(),
            archive_len: 0,
        }
    }

    fn finish_envelope(&mut self) {
        self.signature_digest = None;
    }
}

impl<R: Read> Read for ArchiveReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if let Some(digest) = &mut self.signature_digest {
            digest.update(&buf[..n]);
        }
        Digest::update(&mut self.archive_digest, &buf[..n]);
        self.archive_len += n as u64;
        Ok(n)
    }
}

struct VerifiedProvenance {
    archive_sha256: String,
    archive_len: u64,
    signer_id: String,
    signer_epoch: u32,
    identity: String,
    status: SignerStatus,
}

struct TemporaryFile {
    path: PathBuf,
    committed: bool,
}

impl TemporaryFile {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            committed: false,
        }
    }

    fn create(destination: &Path, private: bool) -> Result<(Self, File)> {
        let path = temporary_output_path(destination)?;
        let file = if private {
            create_private_new(&path)
        } else {
            create_new(&path)
        }?;
        Ok((Self::new(path), file))
    }

    fn commit(mut self, destination: &Path) -> Result<()> {
        // A hard link publishes the completed inode atomically and fails if the destination
        // appeared after our earlier collision check. This avoids rename's overwrite race.
        io_checkpoint("publish.link")?;
        fs::hard_link(&self.path, destination).with_context(|| {
            format!(
                "publishing verified temporary output {} as {}",
                self.path.display(),
                destination.display()
            )
        })?;
        (|| -> Result<()> {
            sync_parent(destination)?;
            io_checkpoint("publish.unlink")?;
            fs::remove_file(&self.path)?;
            self.committed = true;
            sync_parent(destination)
        })().with_context(|| format!(
            "output {} was published, but cleanup or directory durability confirmation failed; inspect it before retrying", destination.display()
        ))
    }

    fn replace(mut self, destination: &Path) -> Result<()> {
        io_checkpoint("publish.rename")?;
        fs::rename(&self.path, destination).with_context(|| {
            format!(
                "replacing {} with temporary file {}",
                destination.display(),
                self.path.display()
            )
        })?;
        self.committed = true;
        sync_parent(destination).with_context(|| format!(
            "output {} was replaced, but directory durability confirmation failed; inspect it before retrying", destination.display()
        ))
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if !self.committed && fs::remove_file(&self.path).is_ok() {
            let _ = sync_parent(&self.path);
        }
    }
}

#[derive(Parser)]
#[command(name = "pqbackup")]
#[command(version)]
#[command(about = "EXPERIMENTAL post-quantum + offline-secret backup encryption")]
#[command(
    long_about = "EXPERIMENTAL post-quantum + offline-secret local backup encryption.\n\nThis reference implementation has not received an independent security audit and must not be the sole protection for irreplaceable, regulated, or high-value data."
)]
#[command(
    after_help = "SECURITY STATUS: Experimental and unaudited. Maintain independent tested backups and keep the ML-KEM seed separate from the root key. See docs/SECURITY_MODEL.md and docs/SUPPORTED_LIMITS.md."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Default)]
struct ProvenanceOptions {
    /// Require trusted provenance as well as authenticated content.
    #[arg(long, requires_all = ["signer_public_key", "signer_policy"])]
    require_provenance: bool,
    #[arg(long, requires = "require_provenance")]
    signer_public_key: Option<PathBuf>,
    #[arg(long, requires = "require_provenance")]
    signer_policy: Option<PathBuf>,
    /// Permit retired signers only under explicit historical policy; never revoked signers.
    #[arg(long, requires = "require_provenance")]
    allow_retired: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Create only the ML-KEM-1024 public key and decapsulation seed.
    KeygenKem {
        #[arg(long)]
        out_dir: PathBuf,
        #[arg(long, default_value = "archive")]
        name: String,
    },

    /// Create only the independent 256-bit root secret.
    KeygenRoot {
        #[arg(long)]
        output: PathBuf,
        /// Stable 32-hex-character root-key ID. Generated randomly when omitted.
        #[arg(long)]
        root_key_id: Option<String>,
        /// Non-negative root-key rotation epoch (for example, 2026).
        #[arg(long, default_value_t = 0)]
        root_key_epoch: u32,
    },

    /// Create an ML-DSA-87 archive-signing seed and public verification key.
    KeygenSigning {
        #[arg(long)]
        out_dir: PathBuf,
        #[arg(long, default_value = "archive-signer")]
        name: String,
        /// Stable 32-hex-character signer-key ID. Generated randomly when omitted.
        #[arg(long)]
        signer_key_id: Option<String>,
        /// Non-negative signer-key rotation epoch.
        #[arg(long, default_value_t = 0)]
        signer_key_epoch: u32,
    },

    /// Encrypt a .tgz (or any file) into a .pqbk archive.
    Seal {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        root_secret: PathBuf,
        #[arg(long, default_value_t = DEFAULT_CHUNK)]
        chunk_size: u32,
        /// Require this 32-hex-character root-key ID before sealing.
        #[arg(long)]
        expect_root_key_id: Option<String>,
        /// Require this root-key epoch before sealing.
        #[arg(long)]
        expect_root_key_epoch: Option<u32>,
    },

    /// Decrypt a .pqbk archive.
    Open {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        secret_key: PathBuf,
        #[arg(long)]
        root_secret: PathBuf,
        #[command(flatten)]
        provenance: ProvenanceOptions,
    },

    /// Cryptographically verify the full archive without writing plaintext.
    Verify {
        input: PathBuf,
        #[arg(long)]
        secret_key: PathBuf,
        #[arg(long)]
        root_secret: PathBuf,
        #[command(flatten)]
        provenance: ProvenanceOptions,
    },

    /// Display non-secret envelope metadata without decrypting.
    Inspect { input: PathBuf },

    /// Add an ML-DSA-87 provenance signature to an unsigned PQBACK02 archive.
    Sign {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        signing_key: PathBuf,
    },

    /// Verify archive provenance against a public key and explicit trust policy.
    ProvenanceVerify {
        input: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        /// Permit a valid historical signature from a policy entry marked retired.
        #[arg(long)]
        allow_retired: bool,
    },

    /// Validate a key/archive file and display only non-secret metadata.
    KeyInfo {
        input: PathBuf,
        #[arg(long, value_enum)]
        kind: KeyFileKind,
    },

    /// Manage a secret-free root-key custody inventory.
    Inventory {
        #[command(subcommand)]
        command: InventoryCommand,
    },

    /// Manage a secret-free signer trust policy.
    SignerPolicy {
        #[command(subcommand)]
        command: SignerPolicyCommand,
    },

    /// Create a safe sample archive and walk through the complete workflow.
    Demo {
        /// New directory for the self-contained demonstration.
        #[arg(long, default_value = "pqbackup-demo")]
        out_dir: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum KeyFileKind {
    Root,
    KemPublic,
    KemSeed,
    Archive,
    SigningPublic,
    SigningSeed,
}

#[derive(Subcommand)]
enum SignerPolicyCommand {
    /// Create a new empty signer policy.
    Init { policy: PathBuf },

    /// Bind one public key and epoch to a trusted identity.
    Add {
        policy: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        identity: String,
        #[arg(long, value_enum, default_value_t = SignerStatus::Trusted)]
        status: SignerStatus,
    },

    /// List signer identities, fingerprints, epochs, and lifecycle states.
    List { policy: PathBuf },

    /// Validate policy structure and duplicate constraints.
    Check { policy: PathBuf },

    /// Change a signer lifecycle state without deleting history.
    SetStatus {
        policy: PathBuf,
        #[arg(long)]
        signer_key_id: String,
        #[arg(long)]
        signer_key_epoch: u32,
        #[arg(long, value_enum)]
        status: SignerStatus,
    },
}

#[derive(Subcommand)]
enum InventoryCommand {
    /// Create a new empty inventory file.
    Init { inventory: PathBuf },

    /// Add one root-key epoch and one or more custody locations.
    Add {
        inventory: PathBuf,
        #[arg(long)]
        root_secret: PathBuf,
        #[arg(long)]
        label: Option<String>,
        #[arg(long, required = true)]
        custody: Vec<String>,
        #[arg(long, value_enum, default_value_t = RootKeyStatus::Active)]
        status: RootKeyStatus,
    },

    /// List inventory metadata without reading recovery secrets.
    List { inventory: PathBuf },

    /// Validate inventory structure and duplicate constraints.
    Check { inventory: PathBuf },

    /// Change lifecycle status without deleting historical metadata.
    SetStatus {
        inventory: PathBuf,
        #[arg(long)]
        root_key_id: String,
        #[arg(long)]
        root_key_epoch: u32,
        #[arg(long, value_enum)]
        status: RootKeyStatus,
    },

    /// Locate custody records matching an archive's requested root ID and epoch.
    Locate {
        inventory: PathBuf,
        archive: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum RootKeyStatus {
    Active,
    Retired,
    Compromised,
    Destroyed,
}

impl std::fmt::Display for RootKeyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Active => "active",
            Self::Retired => "retired",
            Self::Compromised => "compromised",
            Self::Destroyed => "destroyed",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RootKeyInventory {
    format: String,
    #[serde(default)]
    root_keys: Vec<RootKeyRecord>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RootKeyRecord {
    id: String,
    epoch: u32,
    status: RootKeyStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    custody: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum SignerStatus {
    Trusted,
    Retired,
    Revoked,
}

impl std::fmt::Display for SignerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Trusted => "trusted",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignerPolicy {
    format: String,
    #[serde(default)]
    signers: Vec<SignerRecord>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignerRecord {
    id: String,
    epoch: u32,
    identity: String,
    status: SignerStatus,
    public_sha256: String,
}

#[derive(Debug)]
struct Header {
    chunk_size: u32,
    original_len: u64,
    root_key_id: [u8; ROOT_KEY_ID_LEN],
    root_key_epoch: u32,
    hkdf_salt: [u8; 32],
    data_nonce_prefix: [u8; 8],
    wrap_nonce: [u8; 12],
    metadata_nonce: [u8; 12],
    kem_ciphertext: Vec<u8>,
    encrypted_filename: Vec<u8>,
    wrapped_dek: Vec<u8>,
}

struct RootKey {
    id: [u8; ROOT_KEY_ID_LEN],
    epoch: u32,
    secret: Zeroizing<[u8; ROOT_SECRET_LEN]>,
}

#[derive(Clone, Copy, Debug)]
struct RootKeyMetadata {
    id: [u8; ROOT_KEY_ID_LEN],
    epoch: u32,
}

struct SigningSecret {
    id: [u8; SIGNER_KEY_ID_LEN],
    epoch: u32,
    seed: Zeroizing<[u8; MLDSA_SEED_LEN]>,
}

struct SigningPublic {
    id: [u8; SIGNER_KEY_ID_LEN],
    epoch: u32,
    encoded: [u8; MLDSA87_PUBLIC_KEY_LEN],
}

struct ProvenanceTrailer {
    signer_key_id: [u8; SIGNER_KEY_ID_LEN],
    signer_key_epoch: u32,
    signed_len: u64,
    statement: [u8; PROVENANCE_STATEMENT_LEN],
    signature: Vec<u8>,
}

struct ArchiveLayout {
    header: Header,
    envelope_len: u64,
    provenance: Option<ProvenanceTrailer>,
}

struct EncryptedFrame {
    index: u32,
    plain_len: usize,
    is_final: bool,
    ciphertext: Vec<u8>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::KeygenKem { out_dir, name } => keygen_kem(&out_dir, &name),
        Command::KeygenRoot {
            output,
            root_key_id,
            root_key_epoch,
        } => keygen_root(&output, root_key_id.as_deref(), root_key_epoch),
        Command::KeygenSigning {
            out_dir,
            name,
            signer_key_id,
            signer_key_epoch,
        } => keygen_signing(&out_dir, &name, signer_key_id.as_deref(), signer_key_epoch),
        Command::Seal {
            input,
            output,
            public_key,
            root_secret,
            chunk_size,
            expect_root_key_id,
            expect_root_key_epoch,
        } => seal(
            &input,
            output.as_deref(),
            &public_key,
            &root_secret,
            chunk_size,
            expect_root_key_id.as_deref(),
            expect_root_key_epoch,
        ),
        Command::Open {
            input,
            output,
            secret_key,
            root_secret,
            provenance,
        } => open_archive_with_policy(
            &input,
            output.as_deref(),
            &secret_key,
            &root_secret,
            &provenance,
        ),
        Command::Verify {
            input,
            secret_key,
            root_secret,
            provenance,
        } => verify_archive_with_policy(&input, &secret_key, &root_secret, &provenance),
        Command::Inspect { input } => inspect(&input),
        Command::Sign {
            input,
            output,
            signing_key,
        } => sign_archive(&input, output.as_deref(), &signing_key),
        Command::ProvenanceVerify {
            input,
            public_key,
            policy,
            allow_retired,
        } => verify_provenance(&input, &public_key, &policy, allow_retired),
        Command::KeyInfo { input, kind } => key_info(&input, kind),
        Command::Inventory { command } => inventory_command(command),
        Command::SignerPolicy { command } => signer_policy_command(command),
        Command::Demo { out_dir } => demo(&out_dir),
    }
}

fn demo(out_dir: &Path) -> Result<()> {
    eprintln!(
        "warning: demo mode co-locates recovery secrets for disposable testing only; \
         never use its key layout for real archives"
    );
    fs::create_dir(out_dir).with_context(|| {
        format!(
            "creating demo directory {} (choose a new or empty path)",
            out_dir.display()
        )
    })?;
    let keys_dir = out_dir.join("keys");
    let restore_dir = out_dir.join("restore");
    fs::create_dir(&keys_dir)?;
    fs::create_dir(&restore_dir)?;

    let input = out_dir.join("demo-backup.txt");
    let unsigned_archive = out_dir.join("demo-backup.unsigned.pqbk");
    let archive = out_dir.join("demo-backup.pqbk");
    let restored = restore_dir.join("demo-backup.txt");
    let public_key = keys_dir.join("demo.mlkem1024.pub");
    let secret_key = keys_dir.join("demo.mlkem1024.seed");
    let root_key = keys_dir.join("demo.root.key");
    let inventory = out_dir.join("root-key-inventory.toml");
    let signing_seed = keys_dir.join("demo-signer.mldsa87.seed");
    let signing_public = keys_dir.join("demo-signer.mldsa87.pub");
    let signer_policy = out_dir.join("signer-policy.toml");

    println!("Demo directory: {}", out_dir.display());
    println!("\n1. Create a harmless sample backup file.");
    write_new_file(
        &input,
        b"pqbackup demo data: this file is safe to discard.\n",
        false,
    )?;

    println!("\n2. Generate ML-KEM recovery material.");
    keygen_kem(&keys_dir, "demo")?;
    println!("\n3. Generate an independent root key (epoch 1).");
    keygen_root(&root_key, None, 1)?;

    println!("\n4. Record secret-free custody metadata.");
    inventory_init(&inventory)?;
    inventory_add(
        &inventory,
        &root_key,
        Some("disposable demo root"),
        &["demo-only co-located keys directory".to_owned()],
        RootKeyStatus::Active,
    )?;

    println!("\n5. Generate an ML-DSA-87 archive-signing identity.");
    keygen_signing(&keys_dir, "demo-signer", None, 1)?;

    println!("\n6. Create an explicit signer trust policy.");
    signer_policy_init(&signer_policy)?;
    signer_policy_add(
        &signer_policy,
        &signing_public,
        "Disposable pqbackup demo signer",
        SignerStatus::Trusted,
    )?;

    println!("\n7. Seal the sample backup.");
    seal(
        &input,
        Some(&unsigned_archive),
        &public_key,
        &root_key,
        DEFAULT_CHUNK,
        None,
        None,
    )?;

    println!("\n8. Sign the complete encrypted envelope.");
    sign_archive(&unsigned_archive, Some(&archive), &signing_seed)?;

    println!("\n9. Inspect public metadata; the filename and signer identity stay undisclosed.");
    inspect(&archive)?;

    println!("\n10. Verify provenance against the explicit trust policy.");
    verify_provenance(&archive, &signing_public, &signer_policy, false)?;

    println!("\n11. Locate the requested root-key custody record.");
    inventory_locate(&inventory, &archive)?;

    println!("\n12. Verify every encrypted chunk without restoring plaintext.");
    verify_archive(&archive, &secret_key, &root_key)?;

    println!("\n13. Restore the archive to a separate directory.");
    open_archive(&archive, Some(&restored), &secret_key, &root_key)?;

    if fs::read(&input)? != fs::read(&restored)? {
        bail!("demo restore comparison failed");
    }
    println!("\nDemo complete. Restored output matches the input.");
    println!(
        "Inspect the files, then remove {} when finished.",
        out_dir.display()
    );
    Ok(())
}

fn keygen_kem(out_dir: &Path, name: &str) -> Result<()> {
    validate_single_line(name, MAX_FILENAME_LEN, "KEM-key name")?;
    if Path::new(name).file_name().and_then(|value| value.to_str()) != Some(name) {
        bail!("KEM-key name must be a safe single path component");
    }
    create_key_directory(out_dir)?;

    let (dk, ek) = MlKem1024::generate_keypair();
    let seed = dk
        .to_seed()
        .ok_or_else(|| anyhow!("ML-KEM key generation did not retain a seed"))?;
    let seed = Zeroizing::new(seed);
    let public_bytes = ek.to_bytes();

    let pub_path = out_dir.join(format!("{name}.mlkem1024.pub"));
    let sec_path = out_dir.join(format!("{name}.mlkem1024.seed"));

    write_key_pair(
        &pub_path,
        public_bytes.as_slice(),
        &sec_path,
        seed.as_slice(),
    )?;

    println!("Created ML-KEM material:");
    println!("  public key : {}", pub_path.display());
    println!("  secret seed: {}", sec_path.display());
    println!("Keep the public key online if desired; move the seed to protected offline media.");
    Ok(())
}

fn keygen_root(output: &Path, root_key_id: Option<&str>, root_key_epoch: u32) -> Result<()> {
    let id = match root_key_id {
        Some(value) => parse_root_key_id(value)?,
        None => random_array::<ROOT_KEY_ID_LEN>()?,
    };
    let root = RootKey {
        id,
        epoch: root_key_epoch,
        secret: Zeroizing::new(random_array::<ROOT_SECRET_LEN>()?),
    };
    write_new_file(output, &encode_root_key(&root), true)?;
    println!("Created root secret: {}", output.display());
    println!("  root key ID: {}", root_key_id_hex(&root.id));
    println!("  root epoch : {}", root.epoch);
    println!("Keep this secret separate from the ML-KEM decapsulation seed.");
    Ok(())
}

fn keygen_signing(
    out_dir: &Path,
    name: &str,
    signer_key_id: Option<&str>,
    signer_key_epoch: u32,
) -> Result<()> {
    validate_single_line(name, MAX_FILENAME_LEN, "signing-key name")?;
    if Path::new(name).file_name().and_then(|value| value.to_str()) != Some(name) {
        bail!("signing-key name must be a safe single path component");
    }
    create_key_directory(out_dir)?;
    let id = match signer_key_id {
        Some(value) => parse_signer_key_id(value)?,
        None => random_array::<SIGNER_KEY_ID_LEN>()?,
    };
    let secret = SigningSecret {
        id,
        epoch: signer_key_epoch,
        seed: Zeroizing::new(random_array::<MLDSA_SEED_LEN>()?),
    };
    let signing_key = signing_key_from_secret(&secret);
    let verifying_key = signing_key.verifying_key().encode();
    let public = SigningPublic {
        id,
        epoch: signer_key_epoch,
        encoded: verifying_key.as_slice().try_into().unwrap(),
    };

    let public_path = out_dir.join(format!("{name}.mldsa87.pub"));
    let secret_path = out_dir.join(format!("{name}.mldsa87.seed"));
    write_key_pair(
        &public_path,
        &encode_signing_public(&public),
        &secret_path,
        &encode_signing_secret(&secret),
    )?;

    println!("Created ML-DSA-87 provenance material:");
    println!("  public key : {}", public_path.display());
    println!("  secret seed: {}", secret_path.display());
    println!("  signer ID  : {}", signer_key_id_hex(&id));
    println!("  signer epoch: {signer_key_epoch}");
    println!(
        "Keep the signing seed offline and distribute the public key through a trusted channel."
    );
    Ok(())
}

fn key_info(input: &Path, kind: KeyFileKind) -> Result<()> {
    match kind {
        KeyFileKind::Root => {
            let provider = file_root_secret_provider(input)?;
            let metadata = provider.metadata();
            println!("file type       : PQROOT02 root key");
            println!("validation      : valid");
            println!("root key ID     : {}", root_key_id_hex(&metadata.id));
            println!("root key epoch  : {}", metadata.epoch);
            println!("secret bytes    : not displayed");
        }
        KeyFileKind::KemPublic => {
            let bytes = read_exact_sized(input, MLKEM1024_PK_LEN, "ML-KEM public key")?;
            EncapsulationKey::new_from_slice(&bytes)
                .map_err(|_| anyhow!("invalid ML-KEM-1024 public key"))?;
            println!("file type       : ML-KEM-1024 public key");
            println!("validation      : valid");
            println!("public SHA-256  : {}", sha256_hex(&bytes));
        }
        KeyFileKind::KemSeed => {
            let bytes = read_exact_sized_secret(input, MLKEM_SEED_LEN, "ML-KEM secret seed")?;
            let seed = Zeroizing::new(
                <[u8; MLKEM_SEED_LEN]>::try_from(bytes.as_slice())
                    .map_err(|_| anyhow!("invalid ML-KEM seed length"))?,
            );
            let dk = DecapsulationKey::new_from_slice(seed.as_ref())
                .map_err(|_| anyhow!("invalid ML-KEM secret seed"))?;
            let public = dk.encapsulation_key().to_bytes();
            println!("file type       : ML-KEM-1024 decapsulation seed");
            println!("validation      : valid");
            println!("public SHA-256  : {}", sha256_hex(public.as_slice()));
            println!("secret bytes    : not displayed");
        }
        KeyFileKind::Archive => {
            let layout = scan_archive_layout(input)?;
            let header = layout.header;
            println!("file type       : PQBACK02 archive");
            println!("validation      : structurally valid envelope (unauthenticated)");
            println!("root key ID     : {}", root_key_id_hex(&header.root_key_id));
            println!("root key epoch  : {}", header.root_key_epoch);
            println!("filename        : encrypted");
            print_provenance_metadata(layout.provenance.as_ref());
        }
        KeyFileKind::SigningPublic => {
            let public = read_signing_public(input)?;
            println!("file type       : PQPUBS01 ML-DSA-87 public key");
            println!("validation      : valid");
            println!("signer key ID   : {}", signer_key_id_hex(&public.id));
            println!("signer epoch    : {}", public.epoch);
            println!("public SHA-256  : {}", sha256_hex(&public.encoded));
        }
        KeyFileKind::SigningSeed => {
            let secret = read_signing_secret(input)?;
            let public = signing_key_from_secret(&secret).verifying_key().encode();
            println!("file type       : PQSIGN01 ML-DSA-87 signing seed");
            println!("validation      : valid");
            println!("signer key ID   : {}", signer_key_id_hex(&secret.id));
            println!("signer epoch    : {}", secret.epoch);
            println!("public SHA-256  : {}", sha256_hex(public.as_slice()));
            println!("secret bytes    : not displayed");
        }
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn inventory_command(command: InventoryCommand) -> Result<()> {
    match command {
        InventoryCommand::Init { inventory } => inventory_init(&inventory),
        InventoryCommand::Add {
            inventory,
            root_secret,
            label,
            custody,
            status,
        } => inventory_add(&inventory, &root_secret, label.as_deref(), &custody, status),
        InventoryCommand::List { inventory } => inventory_list(&inventory),
        InventoryCommand::Check { inventory } => inventory_check(&inventory),
        InventoryCommand::SetStatus {
            inventory,
            root_key_id,
            root_key_epoch,
            status,
        } => inventory_set_status(&inventory, &root_key_id, root_key_epoch, status),
        InventoryCommand::Locate { inventory, archive } => inventory_locate(&inventory, &archive),
    }
}

fn inventory_init(path: &Path) -> Result<()> {
    let inventory = RootKeyInventory {
        format: INVENTORY_FORMAT.to_owned(),
        root_keys: Vec::new(),
    };
    let encoded = encode_inventory(&inventory)?;
    write_new_file(path, encoded.as_bytes(), true)
        .with_context(|| format!("creating inventory {}", path.display()))?;
    println!("Created root-key inventory: {}", path.display());
    println!("The inventory contains custody metadata only; never put secret bytes in it.");
    Ok(())
}

fn inventory_add(
    inventory_path: &Path,
    root_secret_path: &Path,
    label: Option<&str>,
    custody: &[String],
    status: RootKeyStatus,
) -> Result<()> {
    let mut inventory = read_inventory(inventory_path)?;
    let provider = file_root_secret_provider(root_secret_path)?;
    let metadata = provider.metadata();
    let id = root_key_id_hex(&metadata.id);

    validate_inventory_text(label, custody)?;
    if inventory
        .root_keys
        .iter()
        .any(|record| record.id == id && record.epoch == metadata.epoch)
    {
        bail!(
            "inventory already contains root key {id} epoch {}",
            metadata.epoch
        );
    }

    inventory.root_keys.push(RootKeyRecord {
        id: id.clone(),
        epoch: metadata.epoch,
        status,
        label: label.map(str::to_owned),
        custody: custody.to_vec(),
    });
    inventory
        .root_keys
        .sort_by(|a, b| (&a.id, a.epoch).cmp(&(&b.id, b.epoch)));
    validate_inventory(&inventory)?;
    replace_inventory(inventory_path, &encode_inventory(&inventory)?)?;

    println!("Added root key {id} epoch {} to inventory.", metadata.epoch);
    println!(
        "Recorded {} custody location(s); no secret bytes were stored.",
        custody.len()
    );
    Ok(())
}

fn inventory_list(path: &Path) -> Result<()> {
    let inventory = read_inventory(path)?;
    println!("Inventory: {}", path.display());
    println!("Entries  : {}", inventory.root_keys.len());
    for record in &inventory.root_keys {
        println!("\n{} epoch {} [{}]", record.id, record.epoch, record.status);
        if let Some(label) = &record.label {
            println!("  label   : {label}");
        }
        for location in &record.custody {
            println!("  custody : {location}");
        }
    }
    Ok(())
}

fn inventory_check(path: &Path) -> Result<()> {
    let inventory = read_inventory(path)?;
    println!(
        "Valid {INVENTORY_FORMAT} inventory: {} record(s)",
        inventory.root_keys.len()
    );
    Ok(())
}

fn inventory_set_status(
    path: &Path,
    root_key_id: &str,
    root_key_epoch: u32,
    status: RootKeyStatus,
) -> Result<()> {
    let canonical_id = root_key_id_hex(&parse_root_key_id(root_key_id)?);
    let mut inventory = read_inventory(path)?;
    let record = inventory
        .root_keys
        .iter_mut()
        .find(|record| record.id == canonical_id && record.epoch == root_key_epoch)
        .ok_or_else(|| {
            anyhow!("inventory has no record for root key {canonical_id} epoch {root_key_epoch}")
        })?;
    ensure_root_key_status_transition(record.status, status)?;
    record.status = status;
    replace_inventory(path, &encode_inventory(&inventory)?)?;
    println!("Updated root key {canonical_id} epoch {root_key_epoch} to {status}.");
    Ok(())
}

fn ensure_root_key_status_transition(current: RootKeyStatus, next: RootKeyStatus) -> Result<()> {
    let permitted = matches!(
        (current, next),
        (RootKeyStatus::Active, _)
            | (RootKeyStatus::Retired, RootKeyStatus::Retired)
            | (RootKeyStatus::Retired, RootKeyStatus::Compromised)
            | (RootKeyStatus::Retired, RootKeyStatus::Destroyed)
            | (RootKeyStatus::Compromised, RootKeyStatus::Compromised)
            | (RootKeyStatus::Compromised, RootKeyStatus::Destroyed)
            | (RootKeyStatus::Destroyed, RootKeyStatus::Destroyed)
    );
    if !permitted {
        bail!(
            "root-key lifecycle cannot move from {current} to {next}; create a new epoch instead"
        );
    }
    Ok(())
}

fn inventory_locate(inventory_path: &Path, archive_path: &Path) -> Result<()> {
    let inventory = read_inventory(inventory_path)?;
    let header = read_header_from_file(archive_path)?;
    let id = root_key_id_hex(&header.root_key_id);
    let record = inventory
        .root_keys
        .iter()
        .find(|record| record.id == id && record.epoch == header.root_key_epoch)
        .ok_or_else(|| {
            anyhow!(
                "inventory has no record for root key {id} epoch {}",
                header.root_key_epoch
            )
        })?;

    println!("Archive requests : {id} epoch {}", header.root_key_epoch);
    println!("Inventory status : {}", record.status);
    if let Some(label) = &record.label {
        println!("Label            : {label}");
    }
    for location in &record.custody {
        println!("Custody location : {location}");
    }
    if record.status != RootKeyStatus::Active {
        eprintln!(
            "warning: this root-key record is marked {}; follow the key lifecycle procedure",
            record.status
        );
    }
    Ok(())
}

fn encode_inventory(inventory: &RootKeyInventory) -> Result<String> {
    toml::to_string_pretty(inventory).context("encoding root-key inventory")
}

fn read_inventory(path: &Path) -> Result<RootKeyInventory> {
    let bytes = read_bounded(
        open_material(path, false, "inventory")?,
        MAX_INVENTORY_LEN as usize,
        "inventory",
    )?;
    decode_inventory(std::str::from_utf8(&bytes).context("invalid inventory UTF-8")?)
}

fn decode_inventory(text: &str) -> Result<RootKeyInventory> {
    if text.len() as u64 > MAX_INVENTORY_LEN {
        bail!("inventory exceeds the {MAX_INVENTORY_LEN}-byte safety limit");
    }
    let inventory: RootKeyInventory = toml::from_str(text).context("invalid root-key inventory")?;
    validate_inventory(&inventory)?;
    Ok(inventory)
}

fn validate_inventory(inventory: &RootKeyInventory) -> Result<()> {
    if inventory.format != INVENTORY_FORMAT {
        bail!("unsupported inventory format {}", inventory.format);
    }
    let mut identities = std::collections::HashSet::new();
    for record in &inventory.root_keys {
        let parsed = parse_root_key_id(&record.id)?;
        if root_key_id_hex(&parsed) != record.id {
            bail!("inventory root-key IDs must use canonical lowercase hexadecimal");
        }
        if !identities.insert((parsed, record.epoch)) {
            bail!(
                "duplicate inventory record for root key {} epoch {}",
                record.id,
                record.epoch
            );
        }
        validate_inventory_text(record.label.as_deref(), &record.custody)?;
    }
    Ok(())
}

fn validate_inventory_text(label: Option<&str>, custody: &[String]) -> Result<()> {
    if let Some(label) = label {
        validate_single_line(label, MAX_INVENTORY_LABEL_LEN, "inventory label")?;
    }
    if custody.is_empty() {
        bail!("at least one custody location is required");
    }
    let mut unique = std::collections::HashSet::new();
    for location in custody {
        validate_single_line(location, MAX_CUSTODY_LOCATION_LEN, "custody location")?;
        if !unique.insert(location) {
            bail!("duplicate custody location in inventory record");
        }
    }
    Ok(())
}

fn validate_single_line(value: &str, max_len: usize, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > max_len
        || value.chars().any(|character| {
            character.is_control()
                || matches!(
                    character,
                    '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                        | '\u{200e}'
                        | '\u{200f}'
                        | '\u{061c}'
                )
        })
    {
        bail!("{label} must be a non-empty single line of at most {max_len} bytes");
    }
    Ok(())
}

fn replace_inventory(path: &Path, encoded: &str) -> Result<()> {
    if encoded.len() as u64 > MAX_INVENTORY_LEN {
        bail!("inventory exceeds the {MAX_INVENTORY_LEN}-byte safety limit");
    }
    let (pending, mut file) = TemporaryFile::create(path, true)?;
    file.write_all(encoded.as_bytes())?;
    file.sync_all()?;
    drop(file);
    pending.replace(path)
}

fn signer_policy_command(command: SignerPolicyCommand) -> Result<()> {
    match command {
        SignerPolicyCommand::Init { policy } => signer_policy_init(&policy),
        SignerPolicyCommand::Add {
            policy,
            public_key,
            identity,
            status,
        } => signer_policy_add(&policy, &public_key, &identity, status),
        SignerPolicyCommand::List { policy } => signer_policy_list(&policy),
        SignerPolicyCommand::Check { policy } => signer_policy_check(&policy),
        SignerPolicyCommand::SetStatus {
            policy,
            signer_key_id,
            signer_key_epoch,
            status,
        } => signer_policy_set_status(&policy, &signer_key_id, signer_key_epoch, status),
    }
}

fn signer_policy_init(path: &Path) -> Result<()> {
    let policy = SignerPolicy {
        format: SIGNER_POLICY_FORMAT.to_owned(),
        signers: Vec::new(),
    };
    write_new_file(path, encode_signer_policy(&policy)?.as_bytes(), true)
        .with_context(|| format!("creating signer policy {}", path.display()))?;
    println!("Created signer trust policy: {}", path.display());
    println!("Protect this policy's integrity and distribute it through a trusted channel.");
    Ok(())
}

fn signer_policy_add(
    policy_path: &Path,
    public_key_path: &Path,
    identity: &str,
    status: SignerStatus,
) -> Result<()> {
    validate_single_line(identity, MAX_SIGNER_IDENTITY_LEN, "signer identity")?;
    let public = read_signing_public(public_key_path)?;
    let id = signer_key_id_hex(&public.id);
    let mut policy = read_signer_policy(policy_path)?;
    if policy
        .signers
        .iter()
        .any(|record| record.id == id && record.epoch == public.epoch)
    {
        bail!("policy already contains signer {id} epoch {}", public.epoch);
    }
    policy.signers.push(SignerRecord {
        id: id.clone(),
        epoch: public.epoch,
        identity: identity.to_owned(),
        status,
        public_sha256: sha256_hex(&public.encoded),
    });
    policy
        .signers
        .sort_by(|a, b| (&a.id, a.epoch).cmp(&(&b.id, b.epoch)));
    validate_signer_policy(&policy)?;
    replace_signer_policy(policy_path, &encode_signer_policy(&policy)?)?;
    println!("Added signer {id} epoch {} [{status}].", public.epoch);
    println!("Identity: {identity}");
    Ok(())
}

fn signer_policy_list(path: &Path) -> Result<()> {
    let policy = read_signer_policy(path)?;
    println!("Signer policy: {}", path.display());
    println!("Entries      : {}", policy.signers.len());
    for record in &policy.signers {
        println!("\n{} epoch {} [{}]", record.id, record.epoch, record.status);
        println!("  identity      : {}", record.identity);
        println!("  public SHA-256: {}", record.public_sha256);
    }
    Ok(())
}

fn signer_policy_check(path: &Path) -> Result<()> {
    let policy = read_signer_policy(path)?;
    println!(
        "Valid {SIGNER_POLICY_FORMAT} signer policy: {} record(s)",
        policy.signers.len()
    );
    Ok(())
}

fn signer_policy_set_status(
    path: &Path,
    signer_key_id: &str,
    signer_key_epoch: u32,
    status: SignerStatus,
) -> Result<()> {
    let canonical_id = signer_key_id_hex(&parse_signer_key_id(signer_key_id)?);
    let mut policy = read_signer_policy(path)?;
    let record = policy
        .signers
        .iter_mut()
        .find(|record| record.id == canonical_id && record.epoch == signer_key_epoch)
        .ok_or_else(|| {
            anyhow!("policy has no record for signer {canonical_id} epoch {signer_key_epoch}")
        })?;
    ensure_signer_status_transition(record.status, status)?;
    record.status = status;
    replace_signer_policy(path, &encode_signer_policy(&policy)?)?;
    println!("Updated signer {canonical_id} epoch {signer_key_epoch} to {status}.");
    Ok(())
}

fn ensure_signer_status_transition(current: SignerStatus, next: SignerStatus) -> Result<()> {
    let permitted = matches!(
        (current, next),
        (SignerStatus::Trusted, _)
            | (SignerStatus::Retired, SignerStatus::Retired)
            | (SignerStatus::Retired, SignerStatus::Revoked)
            | (SignerStatus::Revoked, SignerStatus::Revoked)
    );
    if !permitted {
        bail!("signer lifecycle cannot move from {current} to {next}; create a new epoch instead");
    }
    Ok(())
}

fn encode_signer_policy(policy: &SignerPolicy) -> Result<String> {
    toml::to_string_pretty(policy).context("encoding signer trust policy")
}

fn read_signer_policy(path: &Path) -> Result<SignerPolicy> {
    let bytes = read_bounded(
        open_material(path, false, "signer policy")?,
        MAX_SIGNER_POLICY_LEN as usize,
        "signer policy",
    )?;
    decode_signer_policy(std::str::from_utf8(&bytes).context("invalid signer policy UTF-8")?)
}

fn decode_signer_policy(text: &str) -> Result<SignerPolicy> {
    if text.len() as u64 > MAX_SIGNER_POLICY_LEN {
        bail!("signer policy exceeds the {MAX_SIGNER_POLICY_LEN}-byte safety limit");
    }
    let policy: SignerPolicy = toml::from_str(text).context("invalid signer trust policy")?;
    validate_signer_policy(&policy)?;
    Ok(policy)
}

fn validate_signer_policy(policy: &SignerPolicy) -> Result<()> {
    if policy.format != SIGNER_POLICY_FORMAT {
        bail!("unsupported signer policy format {}", policy.format);
    }
    let mut identities = std::collections::HashSet::new();
    for record in &policy.signers {
        let parsed_id = parse_signer_key_id(&record.id)?;
        if signer_key_id_hex(&parsed_id) != record.id {
            bail!("signer IDs must use canonical lowercase hexadecimal");
        }
        if !identities.insert((parsed_id, record.epoch)) {
            bail!(
                "duplicate signer policy record for {} epoch {}",
                record.id,
                record.epoch
            );
        }
        validate_single_line(&record.identity, MAX_SIGNER_IDENTITY_LEN, "signer identity")?;
        parse_sha256_hex(&record.public_sha256)?;
        if record
            .public_sha256
            .bytes()
            .any(|byte| byte.is_ascii_uppercase())
        {
            bail!("public-key fingerprints must use canonical lowercase hexadecimal");
        }
    }
    Ok(())
}

fn replace_signer_policy(path: &Path, encoded: &str) -> Result<()> {
    if encoded.len() as u64 > MAX_SIGNER_POLICY_LEN {
        bail!("signer policy exceeds the {MAX_SIGNER_POLICY_LEN}-byte safety limit");
    }
    let (pending, mut file) = TemporaryFile::create(path, true)?;
    file.write_all(encoded.as_bytes())?;
    file.sync_all()?;
    drop(file);
    pending.replace(path)
}

fn parse_sha256_hex(value: &str) -> Result<[u8; 32]> {
    parse_fixed_hex(value, "SHA-256 fingerprint")
}

fn parse_fixed_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{label} must be exactly {} hexadecimal characters", N * 2);
    }
    let mut result = [0u8; N];
    for (index, slot) in result.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    Ok(result)
}

fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).context("generating random bytes")?;
    Ok(out)
}

fn seal(
    input: &Path,
    output: Option<&Path>,
    public_key_path: &Path,
    root_secret_path: &Path,
    chunk_size: u32,
    expected_root_key_id: Option<&str>,
    expected_root_key_epoch: Option<u32>,
) -> Result<()> {
    if chunk_size == 0 || chunk_size > MAX_CHUNK {
        bail!("chunk size must be between 1 and {MAX_CHUNK} bytes");
    }

    let meta =
        fs::metadata(input).with_context(|| format!("reading metadata for {}", input.display()))?;
    if !meta.is_file() {
        bail!("input must be a regular file");
    }

    let original_len = meta.len();
    validate_archive_geometry(original_len, chunk_size)?;
    let original_name = input
        .file_name()
        .ok_or_else(|| anyhow!("input has no filename"))?
        .to_string_lossy()
        .into_owned();
    validate_filename(&original_name)?;

    let out_path = output
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("{}.pqbk", input.display())));

    let public_bytes = read_exact_sized(public_key_path, MLKEM1024_PK_LEN, "ML-KEM public key")?;
    let root_provider = file_root_secret_provider(root_secret_path)?;
    let root_metadata = root_provider.metadata();
    ensure_expected_root(
        &root_metadata,
        expected_root_key_id,
        expected_root_key_epoch,
    )?;

    let ek = EncapsulationKey::new_from_slice(&public_bytes)
        .map_err(|_| anyhow!("invalid ML-KEM-1024 public key"))?;
    let (kem_ct, shared_secret) = ek.encapsulate();
    let shared_secret = Zeroizing::new(shared_secret);

    let mut hkdf_salt = [0u8; 32];
    let mut data_nonce_prefix = [0u8; 8];
    let mut wrap_nonce = [0u8; 12];
    let mut metadata_nonce = [0u8; 12];
    let mut dek = Zeroizing::new([0u8; DEK_LEN]);

    getrandom::fill(&mut hkdf_salt).context("generating HKDF salt")?;
    getrandom::fill(&mut data_nonce_prefix).context("generating data nonce prefix")?;
    getrandom::fill(&mut wrap_nonce).context("generating wrap nonce")?;
    getrandom::fill(&mut metadata_nonce).context("generating metadata nonce")?;
    getrandom::fill(dek.as_mut()).context("generating data encryption key")?;

    let kek = root_provider.derive_archive_kek(shared_secret.as_slice(), &hkdf_salt)?;
    drop(root_provider);
    drop(shared_secret);

    let metadata_aad = encode_metadata_aad(
        chunk_size,
        original_len,
        &root_metadata.id,
        root_metadata.epoch,
        &hkdf_salt,
        &data_nonce_prefix,
        &wrap_nonce,
        &metadata_nonce,
        kem_ct.as_slice(),
    )?;
    let metadata_cipher =
        Aes256Gcm::new_from_slice(kek.as_ref()).map_err(|_| anyhow!("invalid KEK length"))?;
    let encrypted_filename = metadata_cipher
        .encrypt(
            &aes_nonce(&metadata_nonce),
            Payload {
                msg: original_name.as_bytes(),
                aad: &metadata_aad,
            },
        )
        .map_err(|_| anyhow!("failed to encrypt filename metadata"))?;

    let wrap_aad = encode_wrap_aad(
        chunk_size,
        original_len,
        &root_metadata.id,
        root_metadata.epoch,
        &hkdf_salt,
        &data_nonce_prefix,
        &wrap_nonce,
        &metadata_nonce,
        kem_ct.as_slice(),
        &encrypted_filename,
    )?;

    let wrap_cipher =
        Aes256Gcm::new_from_slice(kek.as_ref()).map_err(|_| anyhow!("invalid KEK length"))?;
    let wrapped_dek = wrap_cipher
        .encrypt(
            &aes_nonce(&wrap_nonce),
            Payload {
                msg: dek.as_ref(),
                aad: &wrap_aad,
            },
        )
        .map_err(|_| anyhow!("failed to wrap data encryption key"))?;
    drop(metadata_cipher);
    drop(wrap_cipher);
    drop(kek);

    let header = Header {
        chunk_size,
        original_len,
        root_key_id: root_metadata.id,
        root_key_epoch: root_metadata.epoch,
        hkdf_salt,
        data_nonce_prefix,
        wrap_nonce,
        metadata_nonce,
        kem_ciphertext: kem_ct.as_slice().to_vec(),
        encrypted_filename,
        wrapped_dek,
    };

    let header_bytes = encode_header(&header)?;
    let header_hash = Sha384::digest(&header_bytes);

    let mut reader = File::open(input).with_context(|| format!("opening {}", input.display()))?;
    if out_path.exists() {
        bail!(
            "refusing to overwrite existing output {}",
            out_path.display()
        );
    }
    let (pending, file) = TemporaryFile::create(&out_path, true)?;
    let mut writer = BufWriter::new(file);

    writer.write_all(&(header_bytes.len() as u32).to_be_bytes())?;
    writer.write_all(&header_bytes)?;

    let data_cipher =
        Aes256Gcm::new_from_slice(dek.as_ref()).map_err(|_| anyhow!("invalid DEK length"))?;
    drop(dek);

    let mut buf = Zeroizing::new(vec![0u8; chunk_size as usize]);
    let mut index: u32 = 0;
    let mut total: u64 = 0;

    loop {
        let n = read_chunk(&mut reader, &mut buf)?;
        if n == 0 {
            // Empty file: write one authenticated final empty chunk.
            if index == 0 {
                write_encrypted_chunk(
                    &mut writer,
                    &data_cipher,
                    &header_hash,
                    &header.data_nonce_prefix,
                    0,
                    true,
                    &[],
                )?;
            }
            break;
        }

        total = total
            .checked_add(n as u64)
            .ok_or_else(|| anyhow!("plaintext length overflow"))?;
        if total > original_len {
            bail!("input grew while being read");
        }
        let is_final = total == original_len;

        write_encrypted_chunk(
            &mut writer,
            &data_cipher,
            &header_hash,
            &header.data_nonce_prefix,
            index,
            is_final,
            &buf[..n],
        )?;

        index = index
            .checked_add(1)
            .ok_or_else(|| anyhow!("too many chunks"))?;

        if is_final {
            let mut extra = [0u8; 1];
            if reader.read(&mut extra)? != 0 {
                bail!("input grew while being read");
            }
            break;
        }
    }

    if total != original_len {
        bail!(
            "input changed while being read: expected {} bytes, read {}",
            original_len,
            total
        );
    }

    writer.flush()?;
    writer.get_ref().sync_all()?;
    drop(writer);
    pending.commit(&out_path)?;

    println!("Sealed {} -> {}", input.display(), out_path.display());
    println!("The .pqbk file alone is insufficient to recover the backup.");
    println!("Recovery requires BOTH the ML-KEM secret seed and the independent root secret.");
    Ok(())
}

fn sign_archive(input: &Path, output: Option<&Path>, signing_key_path: &Path) -> Result<()> {
    let source_layout = scan_archive_layout(input)?;
    if source_layout.provenance.is_some() {
        bail!("archive already has a provenance signature; re-sign from the unsigned archive");
    }
    let out_path = output
        .map(PathBuf::from)
        .unwrap_or_else(|| default_signed_output(input));
    if input == out_path {
        bail!("signed output must differ from the input archive");
    }
    if out_path.exists() {
        bail!(
            "refusing to overwrite existing output {}",
            out_path.display()
        );
    }

    let (pending, file) = TemporaryFile::create(&out_path, true)?;
    let mut source =
        BufReader::new(File::open(input).with_context(|| format!("opening {}", input.display()))?);
    let mut destination = BufWriter::new(file);
    let copied = std::io::copy(&mut source, &mut destination)?;
    destination.flush()?;
    destination.get_ref().sync_all()?;
    drop(destination);

    let copied_layout = scan_archive_layout(&pending.path)?;
    if copied_layout.provenance.is_some() || copied != copied_layout.envelope_len {
        bail!("input changed or gained a signature while it was being copied");
    }
    if copied_layout.envelope_len != source_layout.envelope_len {
        bail!("input changed while it was being copied");
    }

    let secret = read_signing_secret(signing_key_path)?;
    let signing_key = signing_key_from_secret(&secret);
    let statement =
        encode_provenance_statement(&secret.id, secret.epoch, copied_layout.envelope_len);
    let signature: MlDsaSignature<MlDsa87> = signing_key
        .try_sign_digest(|digest| {
            feed_provenance_message(
                digest,
                &pending.path,
                copied_layout.envelope_len,
                &statement,
            )
        })
        .map_err(|_| anyhow!("ML-DSA-87 signing failed"))?;
    signing_key
        .verifying_key()
        .verify_digest(
            |digest| {
                feed_provenance_message(
                    digest,
                    &pending.path,
                    copied_layout.envelope_len,
                    &statement,
                )
            },
            &signature,
        )
        .map_err(|_| anyhow!("internal ML-DSA-87 signature self-check failed"))?;
    let encoded_signature = signature.encode();
    if encoded_signature.len() != MLDSA87_SIGNATURE_LEN {
        bail!("ML-DSA-87 produced an unexpected signature length");
    }

    let mut destination = OpenOptions::new()
        .append(true)
        .open(&pending.path)
        .with_context(|| format!("appending signature to {}", pending.path.display()))?;
    destination.write_all(&statement)?;
    destination.write_all(encoded_signature.as_slice())?;
    destination.sync_all()?;
    drop(destination);

    let signed_layout = scan_archive_layout(&pending.path)?;
    let trailer = signed_layout
        .provenance
        .as_ref()
        .ok_or_else(|| anyhow!("internal error: signed archive has no provenance trailer"))?;
    if trailer.signer_key_id != secret.id || trailer.signer_key_epoch != secret.epoch {
        bail!("internal error: signed archive metadata mismatch");
    }
    let archive_sha256 = sha256_file(&pending.path)?;
    pending.commit(&out_path)?;

    println!("Signed {} -> {}", input.display(), out_path.display());
    println!("Signer ID    : {}", signer_key_id_hex(&secret.id));
    println!("Signer epoch : {}", secret.epoch);
    println!("Archive SHA-256: {archive_sha256}");
    println!("Verify provenance with the public key and a separately trusted signer policy.");
    Ok(())
}

fn verify_provenance(
    input: &Path,
    public_key_path: &Path,
    policy_path: &Path,
    allow_retired: bool,
) -> Result<()> {
    let (_, verified) = verify_provenance_reader(
        archive_input(input)?,
        public_key_path,
        policy_path,
        allow_retired,
        |reader| {
            let layout = scan_archive_reader(reader)?;
            Ok(((), layout.provenance))
        },
    )?;
    println!("Valid archive provenance: {}", input.display());
    print_verified_provenance(&verified);
    Ok(())
}

/// The callback parses (and optionally decrypts) the same stream being hashed.
/// compute_mu uses the same empty context as DigestVerifier; no signature format changes.
fn verify_provenance_reader<R: Read, T>(
    source: R,
    public_key_path: &Path,
    policy_path: &Path,
    allow_retired: bool,
    process: impl FnOnce(&mut ArchiveReader<'_, R>) -> Result<(T, Option<ProvenanceTrailer>)>,
) -> Result<(T, VerifiedProvenance)> {
    let public = read_signing_public(public_key_path)?;
    let verifying_key = verifying_key_from_public(&public)?;
    let mut parsed = None;
    let mu = verifying_key.compute_mu(
        |digest| {
            digest.update(PROVENANCE_DOMAIN);
            let mut reader = ArchiveReader::new(source, Some(digest));
            let result = process(&mut reader).and_then(|(value, trailer)| {
                let trailer =
                    trailer.ok_or_else(|| anyhow!("archive has no provenance signature"))?;
                if reader.signature_digest.is_some()
                    || trailer
                        .signed_len
                        .checked_add((PROVENANCE_STATEMENT_LEN + MLDSA87_SIGNATURE_LEN) as u64)
                        != Some(reader.archive_len)
                {
                    bail!("provenance trailer does not cover the complete encrypted envelope");
                }
                let hash = reader.archive_digest.finalize();
                Ok((value, trailer, hash, reader.archive_len))
            });
            parsed = Some(result);
            // Release the reader's digest borrow before adding the canonical statement.
            match parsed.as_ref().unwrap() {
                Ok((_, trailer, _, _)) => {
                    digest.update(&trailer.statement);
                    Ok(())
                }
                Err(_) => Err(ml_dsa::signature::Error::new()),
            }
        },
        &[],
    );
    let (value, trailer, archive_hash, archive_len) =
        parsed.ok_or_else(|| anyhow!("provenance parser did not run"))??;
    let mu = mu.map_err(|_| anyhow!("provenance digest failed"))?;
    if trailer.signer_key_id != public.id || trailer.signer_key_epoch != public.epoch {
        bail!("public key identity does not match archive signer");
    }
    let signature = MlDsaSignature::<MlDsa87>::try_from(trailer.signature.as_slice())
        .map_err(|_| anyhow!("invalid ML-DSA-87 signature encoding"))?;
    if !verifying_key.verify_mu(&mu, &signature) {
        bail!("archive provenance signature is invalid");
    }
    let policy = read_signer_policy(policy_path)?;
    let id = signer_key_id_hex(&public.id);
    let record = policy
        .signers
        .iter()
        .find(|record| record.id == id && record.epoch == public.epoch)
        .ok_or_else(|| {
            anyhow!(
                "signer {id} epoch {} is not present in the trust policy",
                public.epoch
            )
        })?;
    let fingerprint = sha256_hex(&public.encoded);
    if record.public_sha256 != fingerprint {
        bail!("public key fingerprint does not match the trusted signer policy");
    }
    match record.status {
        SignerStatus::Trusted => {}
        SignerStatus::Retired if allow_retired => {}
        SignerStatus::Retired => bail!(
            "signer {id} epoch {} is retired; use --allow-retired only for approved historical archives",
            public.epoch
        ),
        SignerStatus::Revoked => bail!(
            "signer {id} epoch {} is revoked and cannot be accepted",
            public.epoch
        ),
    }

    Ok((
        value,
        VerifiedProvenance {
            archive_sha256: archive_hash
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            archive_len,
            signer_id: id,
            signer_epoch: public.epoch,
            identity: record.identity.clone(),
            status: record.status,
        },
    ))
}

fn print_verified_provenance(verified: &VerifiedProvenance) {
    println!("Signer identity : {}", verified.identity);
    println!("Signer ID       : {}", verified.signer_id);
    println!("Signer epoch    : {}", verified.signer_epoch);
    println!("Policy status   : {}", verified.status);
    println!("Archive SHA-256 : {}", verified.archive_sha256);
    println!("Archive bytes  : {}", verified.archive_len);
    if verified.status == SignerStatus::Retired {
        eprintln!("warning: accepted a retired signer under explicit historical policy");
    }
}

fn feed_provenance_message<D: Update>(
    digest: &mut D,
    path: &Path,
    signed_len: u64,
    statement: &[u8; PROVENANCE_STATEMENT_LEN],
) -> std::result::Result<(), ml_dsa::signature::Error> {
    digest.update(PROVENANCE_DOMAIN);
    let file = File::open(path).map_err(|_| ml_dsa::signature::Error::new())?;
    let mut reader = BufReader::new(file).take(signed_len);
    let mut remaining = signed_len;
    let mut buffer = [0u8; 64 * 1024];
    while remaining != 0 {
        let read_len = usize::try_from(remaining.min(buffer.len() as u64)).unwrap();
        let count = reader
            .read(&mut buffer[..read_len])
            .map_err(|_| ml_dsa::signature::Error::new())?;
        if count == 0 {
            return Err(ml_dsa::signature::Error::new());
        }
        digest.update(&buffer[..count]);
        remaining -= count as u64;
    }
    digest.update(statement);
    Ok(())
}

fn default_signed_output(input: &Path) -> PathBuf {
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
    let name = input.file_name().unwrap_or_default().to_string_lossy();
    if let Some(stem) = name.strip_suffix(".pqbk") {
        parent.join(format!("{stem}.signed.pqbk"))
    } else {
        parent.join(format!("{name}.signed.pqbk"))
    }
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut reader =
        BufReader::new(File::open(path).with_context(|| format!("opening {}", path.display()))?);
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        Digest::update(&mut digest, &buffer[..count]);
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn open_archive(
    input: &Path,
    output: Option<&Path>,
    secret_key_path: &Path,
    root_secret_path: &Path,
) -> Result<()> {
    open_archive_with_policy(
        input,
        output,
        secret_key_path,
        root_secret_path,
        &ProvenanceOptions::default(),
    )
}

fn open_archive_with_policy(
    input: &Path,
    output: Option<&Path>,
    secret_key_path: &Path,
    root_secret_path: &Path,
    provenance: &ProvenanceOptions,
) -> Result<()> {
    let requested_output = output.map(PathBuf::from);
    if let Some(path) = &requested_output
        && path.exists()
    {
        bail!("refusing to overwrite existing output {}", path.display());
    }

    // A same-directory temporary file permits a single authenticated read even though the
    // default destination name is encrypted inside the header.
    let temp_anchor = requested_output
        .as_deref()
        .unwrap_or_else(|| Path::new("pqbackup-restore"));
    let (pending, mut writer) = TemporaryFile::create(temp_anchor, true)?;

    let (decrypted, verified) = decrypt_with_policy(
        input,
        secret_key_path,
        root_secret_path,
        &mut writer,
        provenance,
    )?;
    let provenance_present = decrypted.provenance.is_some();
    let out_path =
        requested_output.unwrap_or_else(|| PathBuf::from(decrypted.original_name.as_str()));
    if out_path.exists() {
        bail!(
            "refusing to overwrite existing output {}",
            out_path.display()
        );
    }

    writer.flush()?;
    writer.sync_all()?;
    drop(writer);
    pending.commit(&out_path)?;

    println!("Opened {} -> {}", input.display(), out_path.display());
    if let Some(verified) = verified {
        print_verified_provenance(&verified);
    } else if provenance_present {
        println!("Provenance trailer: present but not verified by this command");
        println!("Run `pqbackup provenance-verify` with an explicit signer policy.");
    }
    Ok(())
}

fn verify_archive(input: &Path, secret_key_path: &Path, root_secret_path: &Path) -> Result<()> {
    verify_archive_with_policy(
        input,
        secret_key_path,
        root_secret_path,
        &ProvenanceOptions::default(),
    )
}

fn verify_archive_with_policy(
    input: &Path,
    secret_key_path: &Path,
    root_secret_path: &Path,
    provenance: &ProvenanceOptions,
) -> Result<()> {
    let mut sink = std::io::sink();
    let (decrypted, verified) = decrypt_with_policy(
        input,
        secret_key_path,
        root_secret_path,
        &mut sink,
        provenance,
    )?;
    println!(
        "Verified {}: authenticated {} bytes",
        input.display(),
        decrypted.header.original_len
    );
    if let Some(verified) = verified {
        print_verified_provenance(&verified);
    } else if decrypted.provenance.is_some() {
        println!("Provenance trailer: present but not verified by this command");
        println!("Run `pqbackup provenance-verify` with an explicit signer policy.");
    }
    Ok(())
}

fn decrypt_with_policy<W: Write>(
    input: &Path,
    secret_key_path: &Path,
    root_secret_path: &Path,
    writer: &mut W,
    options: &ProvenanceOptions,
) -> Result<(DecryptedArchive, Option<VerifiedProvenance>)> {
    if !options.require_provenance {
        if options.signer_public_key.is_some()
            || options.signer_policy.is_some()
            || options.allow_retired
        {
            bail!("signer options require --require-provenance");
        }
        return Ok((
            decrypt_archive_to(input, secret_key_path, root_secret_path, writer)?,
            None,
        ));
    }
    let public = options
        .signer_public_key
        .as_deref()
        .ok_or_else(|| anyhow!("--signer-public-key is required"))?;
    let policy = options
        .signer_policy
        .as_deref()
        .ok_or_else(|| anyhow!("--signer-policy is required"))?;
    let (decrypted, verified) = verify_provenance_reader(
        archive_input(input)?,
        public,
        policy,
        options.allow_retired,
        |reader| {
            let mut decrypted =
                decrypt_archive_reader(reader, secret_key_path, root_secret_path, writer)?;
            let trailer = decrypted.provenance.take();
            Ok((decrypted, trailer))
        },
    )?;
    Ok((decrypted, Some(verified)))
}

fn decrypt_archive_to<W: Write>(
    input: &Path,
    secret_key_path: &Path,
    root_secret_path: &Path,
    writer: &mut W,
) -> Result<DecryptedArchive> {
    decrypt_archive_reader(
        &mut ArchiveReader::new(archive_input(input)?, None),
        secret_key_path,
        root_secret_path,
        writer,
    )
}

fn decrypt_archive_reader<R: Read, W: Write>(
    mut reader: &mut ArchiveReader<'_, R>,
    secret_key_path: &Path,
    root_secret_path: &Path,
    writer: &mut W,
) -> Result<DecryptedArchive> {
    let seed_vec = read_exact_sized_secret(secret_key_path, MLKEM_SEED_LEN, "ML-KEM secret seed")?;

    let seed = Zeroizing::new(
        <[u8; MLKEM_SEED_LEN]>::try_from(seed_vec.as_slice())
            .map_err(|_| anyhow!("invalid ML-KEM seed length"))?,
    );
    let root_provider = file_root_secret_provider(root_secret_path)?;
    let root_metadata = root_provider.metadata();

    let dk = DecapsulationKey::new_from_slice(seed.as_ref())
        .map_err(|_| anyhow!("invalid ML-KEM secret seed"))?;

    let header_len = read_u32(&mut reader)? as usize;
    if header_len > MAX_HEADER_LEN {
        bail!("unreasonable header length");
    }

    let mut header_bytes = vec![0u8; header_len];
    reader.read_exact(&mut header_bytes)?;
    let header = decode_header(&header_bytes)?;
    let header_hash = Sha384::digest(&header_bytes);
    ensure_root_metadata(&header, &root_metadata)?;

    let shared_secret = dk
        .decapsulate_slice(&header.kem_ciphertext)
        .map_err(|_| anyhow!("invalid ML-KEM ciphertext"))?;
    let shared_secret = Zeroizing::new(shared_secret);

    let kek = root_provider.derive_archive_kek(shared_secret.as_slice(), &header.hkdf_salt)?;
    drop(root_provider);
    drop(shared_secret);
    drop(dk);
    drop(seed);
    drop(seed_vec);

    let metadata_aad = encode_metadata_aad(
        header.chunk_size,
        header.original_len,
        &header.root_key_id,
        header.root_key_epoch,
        &header.hkdf_salt,
        &header.data_nonce_prefix,
        &header.wrap_nonce,
        &header.metadata_nonce,
        &header.kem_ciphertext,
    )?;
    let metadata_cipher =
        Aes256Gcm::new_from_slice(kek.as_ref()).map_err(|_| anyhow!("invalid KEK length"))?;
    let original_name_bytes = Zeroizing::new(
        metadata_cipher
            .decrypt(
                &aes_nonce(&header.metadata_nonce),
                Payload {
                    msg: &header.encrypted_filename,
                    aad: &metadata_aad,
                },
            )
            .map_err(|_| {
                anyhow!(
                    "filename metadata authentication failed: wrong key/root secret or modified archive"
                )
            })?,
    );
    let original_name = Zeroizing::new(
        std::str::from_utf8(&original_name_bytes)
            .context("invalid encrypted filename")?
            .to_owned(),
    );
    validate_filename(&original_name)?;

    let wrap_aad = encode_wrap_aad(
        header.chunk_size,
        header.original_len,
        &header.root_key_id,
        header.root_key_epoch,
        &header.hkdf_salt,
        &header.data_nonce_prefix,
        &header.wrap_nonce,
        &header.metadata_nonce,
        &header.kem_ciphertext,
        &header.encrypted_filename,
    )?;

    let wrap_cipher =
        Aes256Gcm::new_from_slice(kek.as_ref()).map_err(|_| anyhow!("invalid KEK length"))?;
    let dek_vec = Zeroizing::new(
        wrap_cipher
            .decrypt(
                &aes_nonce(&header.wrap_nonce),
                Payload {
                    msg: &header.wrapped_dek,
                    aad: &wrap_aad,
                },
            )
            .map_err(|_| anyhow!("DEK unwrap failed: wrong key/root secret or modified archive"))?,
    );

    if dek_vec.len() != DEK_LEN {
        bail!("invalid unwrapped DEK length");
    }
    let dek = Zeroizing::new(
        <[u8; DEK_LEN]>::try_from(dek_vec.as_slice())
            .map_err(|_| anyhow!("invalid unwrapped DEK length"))?,
    );

    let cipher =
        Aes256Gcm::new_from_slice(dek.as_ref()).map_err(|_| anyhow!("invalid DEK length"))?;
    drop(dek);
    drop(dek_vec);
    drop(kek);
    drop(wrap_cipher);
    drop(metadata_cipher);
    drop(original_name_bytes);

    let mut expected_index: u32 = 0;
    let mut total: u64 = 0;
    let mut envelope_len = 4u64
        .checked_add(header_len as u64)
        .ok_or_else(|| anyhow!("archive length overflow"))?;

    loop {
        if u64::from(expected_index) >= MAX_DATA_CHUNKS {
            bail!("archive exceeds the {MAX_DATA_CHUNKS}-chunk safety limit");
        }
        let frame = read_encrypted_frame(&mut reader, header.chunk_size)?
            .ok_or_else(|| anyhow!("archive truncated before authenticated final chunk"))?;
        envelope_len = envelope_len
            .checked_add(9 + frame.plain_len as u64 + GCM_TAG_LEN as u64)
            .ok_or_else(|| anyhow!("archive length overflow"))?;

        if frame.index != expected_index {
            bail!(
                "chunk sequence error: expected {expected_index}, got {}",
                frame.index
            );
        }
        if frame.plain_len == 0 && (!frame.is_final || header.original_len != 0) {
            bail!("empty chunks are only valid as the final frame of an empty archive");
        }

        let nonce_bytes = chunk_nonce(&header.data_nonce_prefix, frame.index);
        let aad = chunk_aad(
            &header_hash,
            frame.index,
            frame.plain_len as u32,
            frame.is_final,
        );

        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &aes_nonce(&nonce_bytes),
                    Payload {
                        msg: &frame.ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| anyhow!("authentication failed on chunk {}", frame.index))?,
        );

        writer.write_all(plaintext.as_ref())?;
        total = total
            .checked_add(plaintext.len() as u64)
            .ok_or_else(|| anyhow!("decrypted length overflow"))?;
        if total > header.original_len {
            bail!("decrypted data exceeds declared original length");
        }
        expected_index = expected_index
            .checked_add(1)
            .ok_or_else(|| anyhow!("too many chunks"))?;

        if frame.is_final {
            break;
        }
    }

    if total != header.original_len {
        bail!(
            "decrypted length mismatch: expected {}, got {}",
            header.original_len,
            total
        );
    }

    reader.finish_envelope();
    let provenance = read_optional_provenance(&mut reader, envelope_len)?;

    Ok(DecryptedArchive {
        header,
        original_name,
        provenance,
    })
}

fn read_header_from_file(input: &Path) -> Result<Header> {
    let mut reader = BufReader::new(File::open(input)?);
    let header_len = read_u32(&mut reader)? as usize;
    if header_len > MAX_HEADER_LEN {
        bail!("unreasonable header length");
    }
    let mut header_bytes = vec![0u8; header_len];
    reader.read_exact(&mut header_bytes)?;
    decode_header(&header_bytes)
}

fn temporary_output_path(output: &Path) -> Result<PathBuf> {
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let name = output
        .file_name()
        .ok_or_else(|| anyhow!("output path has no filename"))?
        .to_string_lossy();

    for _ in 0..32 {
        let mut random = [0u8; 8];
        getrandom::fill(&mut random).context("generating temporary filename")?;
        let suffix = u64::from_be_bytes(random);
        let candidate = parent.join(format!(".{name}.{suffix:016x}.tmp"));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    bail!("could not allocate a unique temporary output filename")
}

fn inspect(input: &Path) -> Result<()> {
    let layout = scan_archive_layout(input)?;
    let header = &layout.header;

    println!("format          : PQBACK02");
    println!("version         : {VERSION}");
    println!("KEM             : ML-KEM-1024 / FIPS 203");
    println!("KDF             : HKDF-SHA-384");
    println!("data AEAD       : AES-256-GCM, per-chunk");
    println!("original bytes  : {}", header.original_len);
    println!("chunk size      : {}", header.chunk_size);
    println!("root key ID     : {}", root_key_id_hex(&header.root_key_id));
    println!("root key epoch  : {}", header.root_key_epoch);
    println!("filename        : encrypted");
    println!("KEM ciphertext  : {} bytes", header.kem_ciphertext.len());
    println!("wrapped DEK     : {} bytes", header.wrapped_dek.len());
    println!("envelope bytes  : {}", layout.envelope_len);
    print_provenance_metadata(layout.provenance.as_ref());
    Ok(())
}

fn archive_input(input: &Path) -> Result<BufReader<File>> {
    let file = File::open(input).with_context(|| format!("opening archive {}", input.display()))?;
    if !file.metadata()?.is_file() {
        bail!("archive must be a regular file");
    }
    Ok(BufReader::new(file))
}

fn scan_archive_layout(input: &Path) -> Result<ArchiveLayout> {
    scan_archive_reader(&mut ArchiveReader::new(archive_input(input)?, None))
}

fn scan_archive_reader<R: Read>(mut reader: &mut ArchiveReader<'_, R>) -> Result<ArchiveLayout> {
    let header_len = read_u32(&mut reader)? as usize;
    if header_len > MAX_HEADER_LEN {
        bail!("unreasonable header length");
    }
    let mut header_bytes = vec![0u8; header_len];
    reader
        .read_exact(&mut header_bytes)
        .context("archive truncated inside header")?;
    let header = decode_header(&header_bytes)?;
    let mut envelope_len = 4u64
        .checked_add(header_len as u64)
        .ok_or_else(|| anyhow!("archive length overflow"))?;
    let mut expected_index = 0u32;
    let mut total = 0u64;

    loop {
        if u64::from(expected_index) >= MAX_DATA_CHUNKS {
            bail!("archive exceeds the {MAX_DATA_CHUNKS}-chunk safety limit");
        }
        let frame = read_encrypted_frame(&mut reader, header.chunk_size)?
            .ok_or_else(|| anyhow!("archive truncated before final chunk"))?;
        if frame.index != expected_index {
            bail!(
                "chunk sequence error: expected {expected_index}, got {}",
                frame.index
            );
        }
        if frame.plain_len == 0 && (!frame.is_final || header.original_len != 0) {
            bail!("empty chunks are only valid as the final frame of an empty archive");
        }
        total = total
            .checked_add(frame.plain_len as u64)
            .ok_or_else(|| anyhow!("archive plaintext length overflow"))?;
        if total > header.original_len {
            bail!("archive data exceeds declared original length");
        }
        envelope_len = envelope_len
            .checked_add(9 + frame.plain_len as u64 + GCM_TAG_LEN as u64)
            .ok_or_else(|| anyhow!("archive length overflow"))?;
        expected_index = expected_index
            .checked_add(1)
            .ok_or_else(|| anyhow!("too many chunks"))?;
        if frame.is_final {
            break;
        }
    }
    if total != header.original_len {
        bail!(
            "archive length mismatch: expected {}, got {}",
            header.original_len,
            total
        );
    }
    reader.finish_envelope();
    let provenance = read_optional_provenance(&mut reader, envelope_len)?;
    Ok(ArchiveLayout {
        header,
        envelope_len,
        provenance,
    })
}

fn encode_provenance_statement(
    signer_key_id: &[u8; SIGNER_KEY_ID_LEN],
    signer_key_epoch: u32,
    signed_len: u64,
) -> [u8; PROVENANCE_STATEMENT_LEN] {
    let mut out = [0u8; PROVENANCE_STATEMENT_LEN];
    out[..8].copy_from_slice(PROVENANCE_MAGIC);
    out[8..10].copy_from_slice(&PROVENANCE_VERSION.to_be_bytes());
    out[10..12].copy_from_slice(&SIGNATURE_ALG_MLDSA87.to_be_bytes());
    out[12..12 + SIGNER_KEY_ID_LEN].copy_from_slice(signer_key_id);
    out[12 + SIGNER_KEY_ID_LEN..16 + SIGNER_KEY_ID_LEN]
        .copy_from_slice(&signer_key_epoch.to_be_bytes());
    out[16 + SIGNER_KEY_ID_LEN..24 + SIGNER_KEY_ID_LEN].copy_from_slice(&signed_len.to_be_bytes());
    out[24 + SIGNER_KEY_ID_LEN..].copy_from_slice(&(MLDSA87_SIGNATURE_LEN as u32).to_be_bytes());
    out
}

fn read_optional_provenance<R: Read>(
    reader: &mut R,
    envelope_len: u64,
) -> Result<Option<ProvenanceTrailer>> {
    let mut statement = [0u8; PROVENANCE_STATEMENT_LEN];
    if reader.read(&mut statement[..1])? == 0 {
        return Ok(None);
    }
    reader
        .read_exact(&mut statement[1..])
        .context("archive truncated inside provenance statement")?;
    if &statement[..8] != PROVENANCE_MAGIC {
        bail!("unexpected trailing data after final chunk");
    }
    if u16::from_be_bytes(statement[8..10].try_into().unwrap()) != PROVENANCE_VERSION {
        bail!("unsupported provenance trailer version");
    }
    if u16::from_be_bytes(statement[10..12].try_into().unwrap()) != SIGNATURE_ALG_MLDSA87 {
        bail!("unsupported provenance signature algorithm");
    }
    let signer_key_id = statement[12..12 + SIGNER_KEY_ID_LEN].try_into().unwrap();
    let signer_key_epoch = u32::from_be_bytes(
        statement[12 + SIGNER_KEY_ID_LEN..16 + SIGNER_KEY_ID_LEN]
            .try_into()
            .unwrap(),
    );
    let signed_len = u64::from_be_bytes(
        statement[16 + SIGNER_KEY_ID_LEN..24 + SIGNER_KEY_ID_LEN]
            .try_into()
            .unwrap(),
    );
    if signed_len != envelope_len {
        bail!(
            "provenance signed length {signed_len} does not match envelope length {envelope_len}"
        );
    }
    let signature_len =
        u32::from_be_bytes(statement[24 + SIGNER_KEY_ID_LEN..].try_into().unwrap()) as usize;
    if signature_len != MLDSA87_SIGNATURE_LEN {
        bail!("invalid ML-DSA-87 signature length {signature_len}");
    }
    let mut signature = vec![0u8; signature_len];
    reader
        .read_exact(&mut signature)
        .context("archive truncated inside provenance signature")?;
    let mut trailing = [0u8; 1];
    if reader.read(&mut trailing)? != 0 {
        bail!("unexpected data after provenance trailer");
    }
    Ok(Some(ProvenanceTrailer {
        signer_key_id,
        signer_key_epoch,
        signed_len,
        statement,
        signature,
    }))
}

fn print_provenance_metadata(provenance: Option<&ProvenanceTrailer>) {
    match provenance {
        None => println!("provenance      : unsigned"),
        Some(trailer) => {
            println!("provenance      : signature present (unverified)");
            println!("signature       : ML-DSA-87 / FIPS 204");
            println!(
                "signer key ID    : {} (unverified)",
                signer_key_id_hex(&trailer.signer_key_id)
            );
            println!(
                "signer epoch     : {} (unverified)",
                trailer.signer_key_epoch
            );
        }
    }
}

fn derive_kek(
    shared: &[u8],
    root: &[u8; ROOT_SECRET_LEN],
    salt: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    // Fixed-length composition: 32-byte ML-KEM shared secret || 32-byte independent root secret.
    let mut ikm = Zeroizing::new([0u8; 64]);
    if shared.len() != 32 {
        bail!("unexpected ML-KEM shared secret length");
    }
    ikm[..32].copy_from_slice(shared);
    ikm[32..].copy_from_slice(root);

    let hk = Hkdf::<Sha384>::new(Some(salt), ikm.as_ref());
    let mut kek = Zeroizing::new([0u8; 32]);
    hk.expand(b"pqbackup/v2/archive-kek/aes-256-gcm", kek.as_mut())
        .map_err(|_| anyhow!("HKDF expansion failed"))?;
    ikm.zeroize();
    Ok(kek)
}

// Keeping each authenticated field explicit makes the byte-level format reviewable.
#[allow(clippy::too_many_arguments)]
fn encode_wrap_aad(
    chunk_size: u32,
    original_len: u64,
    root_key_id: &[u8; ROOT_KEY_ID_LEN],
    root_key_epoch: u32,
    hkdf_salt: &[u8; 32],
    data_nonce_prefix: &[u8; 8],
    wrap_nonce: &[u8; 12],
    metadata_nonce: &[u8; 12],
    kem_ciphertext: &[u8],
    encrypted_filename: &[u8],
) -> Result<Vec<u8>> {
    let mut v = b"pqbackup/v2/wrap".to_vec();
    v.extend_from_slice(&encode_public_header(
        chunk_size,
        original_len,
        root_key_id,
        root_key_epoch,
        hkdf_salt,
        data_nonce_prefix,
        wrap_nonce,
        metadata_nonce,
        kem_ciphertext,
    )?);
    if encrypted_filename.len() > u16::MAX as usize {
        bail!("encrypted filename too long");
    }
    v.extend_from_slice(&(encrypted_filename.len() as u16).to_be_bytes());
    v.extend_from_slice(encrypted_filename);
    Ok(v)
}

#[allow(clippy::too_many_arguments)]
fn encode_metadata_aad(
    chunk_size: u32,
    original_len: u64,
    root_key_id: &[u8; ROOT_KEY_ID_LEN],
    root_key_epoch: u32,
    hkdf_salt: &[u8; 32],
    data_nonce_prefix: &[u8; 8],
    wrap_nonce: &[u8; 12],
    metadata_nonce: &[u8; 12],
    kem_ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let mut v = b"pqbackup/v2/metadata".to_vec();
    v.extend_from_slice(&encode_public_header(
        chunk_size,
        original_len,
        root_key_id,
        root_key_epoch,
        hkdf_salt,
        data_nonce_prefix,
        wrap_nonce,
        metadata_nonce,
        kem_ciphertext,
    )?);
    Ok(v)
}

#[allow(clippy::too_many_arguments)]
fn encode_public_header(
    chunk_size: u32,
    original_len: u64,
    root_key_id: &[u8; ROOT_KEY_ID_LEN],
    root_key_epoch: u32,
    hkdf_salt: &[u8; 32],
    data_nonce_prefix: &[u8; 8],
    wrap_nonce: &[u8; 12],
    metadata_nonce: &[u8; 12],
    kem_ciphertext: &[u8],
) -> Result<Vec<u8>> {
    if kem_ciphertext.len() != MLKEM1024_CT_LEN {
        bail!("unexpected ML-KEM ciphertext length");
    }
    let mut v = Vec::new();
    v.extend_from_slice(MAGIC);
    v.extend_from_slice(&VERSION.to_be_bytes());
    v.extend_from_slice(&KEM_ID_MLKEM1024.to_be_bytes());
    v.extend_from_slice(&KDF_ID_HKDF_SHA384.to_be_bytes());
    v.extend_from_slice(&AEAD_ID_AES256GCM.to_be_bytes());
    v.extend_from_slice(&chunk_size.to_be_bytes());
    v.extend_from_slice(&original_len.to_be_bytes());
    v.extend_from_slice(root_key_id);
    v.extend_from_slice(&root_key_epoch.to_be_bytes());
    v.extend_from_slice(hkdf_salt);
    v.extend_from_slice(data_nonce_prefix);
    v.extend_from_slice(wrap_nonce);
    v.extend_from_slice(metadata_nonce);
    v.extend_from_slice(&(kem_ciphertext.len() as u32).to_be_bytes());
    v.extend_from_slice(kem_ciphertext);
    Ok(v)
}

fn encode_header(h: &Header) -> Result<Vec<u8>> {
    if h.kem_ciphertext.len() != MLKEM1024_CT_LEN {
        bail!("unexpected ML-KEM-1024 ciphertext length");
    }
    if h.wrapped_dek.len() != DEK_LEN + GCM_TAG_LEN {
        bail!("unexpected wrapped DEK length");
    }
    if h.encrypted_filename.len() < GCM_TAG_LEN
        || h.encrypted_filename.len() > MAX_FILENAME_LEN + GCM_TAG_LEN
    {
        bail!("unexpected encrypted filename length");
    }

    let mut v = encode_public_header(
        h.chunk_size,
        h.original_len,
        &h.root_key_id,
        h.root_key_epoch,
        &h.hkdf_salt,
        &h.data_nonce_prefix,
        &h.wrap_nonce,
        &h.metadata_nonce,
        &h.kem_ciphertext,
    )?;
    v.extend_from_slice(&(h.encrypted_filename.len() as u16).to_be_bytes());
    v.extend_from_slice(&h.encrypted_filename);
    v.extend_from_slice(&(h.wrapped_dek.len() as u16).to_be_bytes());
    v.extend_from_slice(&h.wrapped_dek);
    Ok(v)
}

fn decode_header(bytes: &[u8]) -> Result<Header> {
    let mut c = Cursor::new(bytes);

    let magic = c.take(8)?;
    if magic != MAGIC {
        bail!("not a pqbackup archive");
    }

    let version = c.u16()?;
    if version != VERSION {
        bail!("unsupported version {version}");
    }

    if c.u16()? != KEM_ID_MLKEM1024 {
        bail!("unsupported KEM");
    }
    if c.u16()? != KDF_ID_HKDF_SHA384 {
        bail!("unsupported KDF");
    }
    if c.u16()? != AEAD_ID_AES256GCM {
        bail!("unsupported AEAD");
    }

    let chunk_size = c.u32()?;
    if chunk_size == 0 || chunk_size > MAX_CHUNK {
        bail!("invalid chunk size");
    }

    let original_len = c.u64()?;
    validate_archive_geometry(original_len, chunk_size)?;
    let root_key_id: [u8; ROOT_KEY_ID_LEN] = c.take(ROOT_KEY_ID_LEN)?.try_into().unwrap();
    let root_key_epoch = c.u32()?;

    let hkdf_salt: [u8; 32] = c.take(32)?.try_into().unwrap();
    let data_nonce_prefix: [u8; 8] = c.take(8)?.try_into().unwrap();
    let wrap_nonce: [u8; 12] = c.take(12)?.try_into().unwrap();
    let metadata_nonce: [u8; 12] = c.take(12)?.try_into().unwrap();

    let kem_len = c.u32()? as usize;
    if kem_len != MLKEM1024_CT_LEN {
        bail!("unexpected ML-KEM ciphertext length");
    }
    let kem_ciphertext = c.take(kem_len)?.to_vec();

    let filename_len = c.u16()? as usize;
    if !(GCM_TAG_LEN..=MAX_FILENAME_LEN + GCM_TAG_LEN).contains(&filename_len) {
        bail!("invalid encrypted filename length");
    }
    let encrypted_filename = c.take(filename_len)?.to_vec();

    let wrapped_len = c.u16()? as usize;
    if wrapped_len != DEK_LEN + GCM_TAG_LEN {
        bail!("unexpected wrapped DEK length");
    }
    let wrapped_dek = c.take(wrapped_len)?.to_vec();

    if !c.at_end() {
        bail!("unexpected extra header bytes");
    }

    Ok(Header {
        chunk_size,
        original_len,
        root_key_id,
        root_key_epoch,
        hkdf_salt,
        data_nonce_prefix,
        wrap_nonce,
        metadata_nonce,
        kem_ciphertext,
        encrypted_filename,
        wrapped_dek,
    })
}

fn write_encrypted_chunk<W: Write>(
    writer: &mut W,
    cipher: &Aes256Gcm,
    header_hash: &[u8],
    nonce_prefix: &[u8; 8],
    index: u32,
    is_final: bool,
    plaintext: &[u8],
) -> Result<()> {
    let nonce_bytes = chunk_nonce(nonce_prefix, index);
    let aad = chunk_aad(header_hash, index, plaintext.len() as u32, is_final);

    let ciphertext = cipher
        .encrypt(
            &aes_nonce(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("chunk encryption failed"))?;

    writer.write_all(&index.to_be_bytes())?;
    writer.write_all(&(plaintext.len() as u32).to_be_bytes())?;
    writer.write_all(&[if is_final { 1 } else { 0 }])?;
    writer.write_all(&ciphertext)?;
    Ok(())
}

fn chunk_nonce(prefix: &[u8; 8], index: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(prefix);
    nonce[8..].copy_from_slice(&index.to_be_bytes());
    nonce
}

fn aes_nonce(bytes: &[u8; 12]) -> Nonce<aes_gcm::aead::consts::U12> {
    (*bytes).into()
}

fn chunk_aad(header_hash: &[u8], index: u32, plain_len: u32, is_final: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + header_hash.len());
    aad.extend_from_slice(b"pqbackup/v2/data-chunk");
    aad.extend_from_slice(header_hash);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&plain_len.to_be_bytes());
    aad.push(if is_final { 1 } else { 0 });
    aad
}

fn read_chunk<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = reader.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

fn read_encrypted_frame<R: Read>(
    reader: &mut R,
    chunk_size: u32,
) -> Result<Option<EncryptedFrame>> {
    let mut frame_header = [0u8; 9];
    if reader.read(&mut frame_header[..1])? == 0 {
        return Ok(None);
    }
    reader
        .read_exact(&mut frame_header[1..])
        .context("archive truncated inside frame header")?;

    let index = u32::from_be_bytes(frame_header[0..4].try_into().unwrap());
    let plain_len = u32::from_be_bytes(frame_header[4..8].try_into().unwrap()) as usize;
    let flags = frame_header[8];
    if flags & !0x01 != 0 {
        bail!("unsupported chunk flags");
    }
    if plain_len > chunk_size as usize || plain_len > MAX_CHUNK as usize {
        bail!("chunk exceeds declared chunk size");
    }
    let ciphertext_len = plain_len
        .checked_add(GCM_TAG_LEN)
        .ok_or_else(|| anyhow!("chunk ciphertext length overflow"))?;
    let mut ciphertext = vec![0u8; ciphertext_len];
    reader
        .read_exact(&mut ciphertext)
        .context("archive truncated inside chunk")?;

    Ok(Some(EncryptedFrame {
        index,
        plain_len,
        is_final: flags & 0x01 != 0,
        ciphertext,
    }))
}

fn create_new(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(Into::into)
}

fn create_private_new(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    options.open(path).map_err(Into::into)
}

fn sync_parent(path: &Path) -> Result<()> {
    io_checkpoint("directory.sync")?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)?
        .sync_all()
        .with_context(|| format!("synchronizing directory {}", parent.display()))
}

// Fault injection is confined to the unit-test binary and current test thread.
#[cfg(test)]
thread_local! {
    static IO_FAILURE: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}

fn io_checkpoint(_stage: &'static str) -> std::io::Result<()> {
    #[cfg(test)]
    if IO_FAILURE.with(|failure| {
        if failure.get() == Some(_stage) {
            failure.set(None);
            true
        } else {
            false
        }
    }) {
        return Err(std::io::Error::other(format!("injected {_stage} failure")));
    }
    Ok(())
}

fn stage_file(path: &Path, data: &[u8], secret: bool) -> Result<TemporaryFile> {
    stage_file_with(path, secret, |file| {
        io_checkpoint("stage.write")?;
        file.write_all(data)?;
        Ok(())
    })
}

fn stage_file_with(
    path: &Path,
    secret: bool,
    write: impl FnOnce(&mut File) -> Result<()>,
) -> Result<TemporaryFile> {
    let (pending, mut file) = TemporaryFile::create(path, secret)?;
    write(&mut file)?;
    io_checkpoint("stage.flush")?;
    file.flush()?;
    io_checkpoint("stage.sync")?;
    file.sync_all()?;
    drop(file);
    Ok(pending)
}

fn create_key_directory(path: &Path) -> Result<()> {
    let mut missing = Vec::new();
    let mut current = path;
    while !current.as_os_str().is_empty() {
        match fs::metadata(current) {
            Ok(metadata) if metadata.is_dir() => break,
            Ok(_) => bail!(
                "key directory path is not a directory: {}",
                current.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => missing.push(current),
            Err(error) => return Err(error.into()),
        }
        current = current.parent().unwrap_or_else(|| Path::new("."));
    }
    for directory in missing.into_iter().rev() {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(directory)
            .with_context(|| format!("creating key directory {}", directory.display()))?;
        sync_parent(directory)?;
    }
    Ok(())
}

fn write_new_file(path: &Path, data: &[u8], secret: bool) -> Result<()> {
    stage_file(path, data, secret)?.commit(path)
}

fn write_key_pair(
    public_path: &Path,
    public: &[u8],
    secret_path: &Path,
    secret: &[u8],
) -> Result<()> {
    for path in [public_path, secret_path] {
        match fs::symlink_metadata(path) {
            Ok(_) => bail!("refusing to overwrite existing key {}", path.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let public_pending = stage_file(public_path, public, false)?;
    let secret_pending = stage_file(secret_path, secret, true)?;
    // There is no portable atomic two-file publication. Preserve the secret if
    // the second publication fails; never remove a published recovery secret.
    secret_pending.commit(secret_path).with_context(|| {
        format!(
            "key-pair generation did not complete; inspect {} before retrying",
            secret_path.display()
        )
    })?;
    (|| -> Result<()> {
        io_checkpoint("pair.public")?;
        public_pending.commit(public_path)
    })().with_context(|| format!(
        "key-pair generation incomplete: secret retained at {}; inspect public output {} before retrying", secret_path.display(), public_path.display()
    ))
}

fn open_material(path: &Path, secret: bool, label: &str) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // NONBLOCK prevents a FIFO from hanging before descriptor validation.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).with_context(|| {
        format!(
            "opening {label} {}; use a regular file and an explicit non-symlink filename",
            path.display()
        )
    })?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!("{label} must be a regular file");
    }
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid takes no arguments and has no memory-safety preconditions.
        validate_secret_permissions(metadata.uid(), metadata.mode(), unsafe { libc::geteuid() })
            .with_context(|| format!("unsafe permissions on {label} {}", path.display()))?;
    }
    #[cfg(not(unix))]
    if secret {
        bail!("strict secret-file access requires a supported Unix platform");
    }
    Ok(file)
}

#[cfg(unix)]
fn validate_secret_permissions(owner: u32, mode: u32, current_user: u32) -> Result<()> {
    if owner != current_user {
        bail!("secret must be owned by the current effective user");
    }
    if mode & 0o077 != 0 {
        bail!(
            "secret grants group/other permissions; restrict it to mode 0600 or 0400 after checking custody and ACLs"
        );
    }
    Ok(())
}

fn read_bounded<R: Read>(reader: R, maximum: usize, label: &str) -> Result<Zeroizing<Vec<u8>>> {
    let limit = maximum
        .checked_add(1)
        .ok_or_else(|| anyhow!("read limit overflow"))?;
    // Fixed capacity prevents secret-bearing reallocations while reading.
    let mut data = Zeroizing::new(vec![0u8; limit]);
    let mut reader = reader.take(limit as u64);
    let mut used = 0;
    while used < limit {
        match reader.read(&mut data[used..]) {
            Ok(0) => break,
            Ok(n) => used += n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error).with_context(|| format!("reading {label}")),
        }
    }
    if used > maximum {
        bail!("{label} exceeds the {maximum}-byte safety limit");
    }
    data.truncate(used);
    Ok(data)
}

fn read_exact_sized(path: &Path, expected: usize, label: &str) -> Result<Zeroizing<Vec<u8>>> {
    read_material(path, expected, label, false)
}

fn read_exact_sized_secret(
    path: &Path,
    expected: usize,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    read_material(path, expected, label, true)
}

fn read_material(
    path: &Path,
    expected: usize,
    label: &str,
    secret: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    let data = read_bounded(open_material(path, secret, label)?, expected, label)?;
    if data.len() != expected {
        bail!(
            "{label} must be exactly {expected} bytes; got {}",
            data.len()
        );
    }
    Ok(data)
}

fn encode_root_key(root: &RootKey) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(
        8 + 2 + ROOT_KEY_ID_LEN + 4 + ROOT_SECRET_LEN,
    ));
    out.extend_from_slice(ROOT_MAGIC);
    out.extend_from_slice(&ROOT_VERSION.to_be_bytes());
    out.extend_from_slice(&root.id);
    out.extend_from_slice(&root.epoch.to_be_bytes());
    out.extend_from_slice(root.secret.as_ref());
    out
}

trait RootSecretProvider {
    fn metadata(&self) -> RootKeyMetadata;
    fn derive_archive_kek(
        &self,
        shared_secret: &[u8],
        salt: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>>;
}

struct FileRootSecretProvider {
    root: RootKey,
}

impl FileRootSecretProvider {
    fn open(path: &Path) -> Result<Self> {
        let data = read_exact_sized_secret(
            path,
            8 + 2 + ROOT_KEY_ID_LEN + 4 + ROOT_SECRET_LEN,
            "root key",
        )?;
        Ok(Self {
            root: decode_root_key(&data)?,
        })
    }
}

impl RootSecretProvider for FileRootSecretProvider {
    fn metadata(&self) -> RootKeyMetadata {
        RootKeyMetadata {
            id: self.root.id,
            epoch: self.root.epoch,
        }
    }

    fn derive_archive_kek(
        &self,
        shared_secret: &[u8],
        salt: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>> {
        derive_kek(shared_secret, &self.root.secret, salt)
    }
}

fn file_root_secret_provider(path: &Path) -> Result<Box<dyn RootSecretProvider>> {
    Ok(Box::new(FileRootSecretProvider::open(path)?))
}

#[cfg(test)]
fn read_root_key(path: &Path) -> Result<RootKey> {
    Ok(FileRootSecretProvider::open(path)?.root)
}

fn decode_root_key(data: &[u8]) -> Result<RootKey> {
    let expected = 8 + 2 + ROOT_KEY_ID_LEN + 4 + ROOT_SECRET_LEN;
    if data.len() != expected {
        bail!(
            "root key must be a PQROOT02 key file ({expected} bytes); got {}",
            data.len()
        );
    }
    if &data[..8] != ROOT_MAGIC {
        bail!("root key is not a PQROOT02 key file; generate a new v2 root key");
    }
    if u16::from_be_bytes(data[8..10].try_into().unwrap()) != ROOT_VERSION {
        bail!("unsupported root key version");
    }
    let id = data[10..10 + ROOT_KEY_ID_LEN].try_into().unwrap();
    let epoch = u32::from_be_bytes(
        data[10 + ROOT_KEY_ID_LEN..14 + ROOT_KEY_ID_LEN]
            .try_into()
            .unwrap(),
    );
    let secret = Zeroizing::new(data[14 + ROOT_KEY_ID_LEN..].try_into().unwrap());
    Ok(RootKey { id, epoch, secret })
}

fn encode_signing_secret(secret: &SigningSecret) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(
        8 + 2 + 2 + SIGNER_KEY_ID_LEN + 4 + MLDSA_SEED_LEN,
    ));
    out.extend_from_slice(SIGNING_SECRET_MAGIC);
    out.extend_from_slice(&SIGNING_KEY_VERSION.to_be_bytes());
    out.extend_from_slice(&SIGNATURE_ALG_MLDSA87.to_be_bytes());
    out.extend_from_slice(&secret.id);
    out.extend_from_slice(&secret.epoch.to_be_bytes());
    out.extend_from_slice(secret.seed.as_ref());
    out
}

fn decode_signing_secret(data: &[u8]) -> Result<SigningSecret> {
    let expected = 8 + 2 + 2 + SIGNER_KEY_ID_LEN + 4 + MLDSA_SEED_LEN;
    if data.len() != expected {
        bail!(
            "signing key must be a PQSIGN01 key file ({expected} bytes); got {}",
            data.len()
        );
    }
    if &data[..8] != SIGNING_SECRET_MAGIC {
        bail!("signing key is not a PQSIGN01 key file");
    }
    if u16::from_be_bytes(data[8..10].try_into().unwrap()) != SIGNING_KEY_VERSION {
        bail!("unsupported signing-key version");
    }
    if u16::from_be_bytes(data[10..12].try_into().unwrap()) != SIGNATURE_ALG_MLDSA87 {
        bail!("unsupported signing-key algorithm");
    }
    Ok(SigningSecret {
        id: data[12..12 + SIGNER_KEY_ID_LEN].try_into().unwrap(),
        epoch: u32::from_be_bytes(
            data[12 + SIGNER_KEY_ID_LEN..16 + SIGNER_KEY_ID_LEN]
                .try_into()
                .unwrap(),
        ),
        seed: Zeroizing::new(data[16 + SIGNER_KEY_ID_LEN..].try_into().unwrap()),
    })
}

fn read_signing_secret(path: &Path) -> Result<SigningSecret> {
    let expected = 8 + 2 + 2 + SIGNER_KEY_ID_LEN + 4 + MLDSA_SEED_LEN;
    let data = read_exact_sized_secret(path, expected, "ML-DSA-87 signing seed")?;
    decode_signing_secret(data.as_ref())
}

fn encode_signing_public(public: &SigningPublic) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 2 + 2 + SIGNER_KEY_ID_LEN + 4 + MLDSA87_PUBLIC_KEY_LEN);
    out.extend_from_slice(SIGNING_PUBLIC_MAGIC);
    out.extend_from_slice(&SIGNING_KEY_VERSION.to_be_bytes());
    out.extend_from_slice(&SIGNATURE_ALG_MLDSA87.to_be_bytes());
    out.extend_from_slice(&public.id);
    out.extend_from_slice(&public.epoch.to_be_bytes());
    out.extend_from_slice(&public.encoded);
    out
}

fn decode_signing_public(data: &[u8]) -> Result<SigningPublic> {
    let expected = 8 + 2 + 2 + SIGNER_KEY_ID_LEN + 4 + MLDSA87_PUBLIC_KEY_LEN;
    if data.len() != expected {
        bail!(
            "public signing key must be a PQPUBS01 key file ({expected} bytes); got {}",
            data.len()
        );
    }
    if &data[..8] != SIGNING_PUBLIC_MAGIC {
        bail!("public signing key is not a PQPUBS01 key file");
    }
    if u16::from_be_bytes(data[8..10].try_into().unwrap()) != SIGNING_KEY_VERSION {
        bail!("unsupported public signing-key version");
    }
    if u16::from_be_bytes(data[10..12].try_into().unwrap()) != SIGNATURE_ALG_MLDSA87 {
        bail!("unsupported public signing-key algorithm");
    }
    let encoded: [u8; MLDSA87_PUBLIC_KEY_LEN] = data[16 + SIGNER_KEY_ID_LEN..].try_into().unwrap();
    let encoded_key = EncodedVerifyingKey::<MlDsa87>::try_from(encoded.as_slice())
        .map_err(|_| anyhow!("invalid ML-DSA-87 public-key length"))?;
    let key = MlDsaVerifyingKey::<MlDsa87>::decode(&encoded_key);
    if key.encode().as_slice() != encoded {
        bail!("non-canonical ML-DSA-87 public key");
    }
    Ok(SigningPublic {
        id: data[12..12 + SIGNER_KEY_ID_LEN].try_into().unwrap(),
        epoch: u32::from_be_bytes(
            data[12 + SIGNER_KEY_ID_LEN..16 + SIGNER_KEY_ID_LEN]
                .try_into()
                .unwrap(),
        ),
        encoded,
    })
}

fn read_signing_public(path: &Path) -> Result<SigningPublic> {
    let expected = 8 + 2 + 2 + SIGNER_KEY_ID_LEN + 4 + MLDSA87_PUBLIC_KEY_LEN;
    let data = read_exact_sized(path, expected, "ML-DSA-87 public key")?;
    decode_signing_public(&data)
}

fn signing_key_from_secret(secret: &SigningSecret) -> MlDsaSigningKey<MlDsa87> {
    let mut seed = MlDsaSeed::from(*secret.seed);
    let signing_key = MlDsaSigningKey::<MlDsa87>::from_seed(&seed);
    seed.as_mut_slice().zeroize();
    signing_key
}

fn verifying_key_from_public(public: &SigningPublic) -> Result<MlDsaVerifyingKey<MlDsa87>> {
    let encoded = EncodedVerifyingKey::<MlDsa87>::try_from(public.encoded.as_slice())
        .map_err(|_| anyhow!("invalid ML-DSA-87 public-key length"))?;
    Ok(MlDsaVerifyingKey::<MlDsa87>::decode(&encoded))
}

fn parse_root_key_id(value: &str) -> Result<[u8; ROOT_KEY_ID_LEN]> {
    if value.len() != ROOT_KEY_ID_LEN * 2 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!(
            "root key ID must be exactly {} hexadecimal characters",
            ROOT_KEY_ID_LEN * 2
        );
    }
    let mut id = [0u8; ROOT_KEY_ID_LEN];
    for (i, slot) in id.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).unwrap();
    }
    Ok(id)
}

fn root_key_id_hex(id: &[u8; ROOT_KEY_ID_LEN]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_signer_key_id(value: &str) -> Result<[u8; SIGNER_KEY_ID_LEN]> {
    parse_fixed_hex(value, "signer key ID")
}

fn signer_key_id_hex(id: &[u8; SIGNER_KEY_ID_LEN]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validate_filename(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > MAX_FILENAME_LEN
        || name == "."
        || name == ".."
        || name.as_bytes().contains(&0)
        || Path::new(name).file_name().and_then(|n| n.to_str()) != Some(name)
    {
        bail!("encrypted filename is not a safe single path component");
    }
    Ok(())
}

fn validate_archive_geometry(original_len: u64, chunk_size: u32) -> Result<u64> {
    if chunk_size == 0 || chunk_size > MAX_CHUNK {
        bail!("chunk size must be between 1 and {MAX_CHUNK} bytes");
    }
    if original_len > MAX_PLAINTEXT_LEN {
        bail!("original length exceeds the {MAX_PLAINTEXT_LEN}-byte safety limit");
    }

    let chunk_count = if original_len == 0 {
        1
    } else {
        original_len.div_ceil(u64::from(chunk_size))
    };
    if chunk_count > MAX_DATA_CHUNKS {
        bail!("archive would exceed the {MAX_DATA_CHUNKS}-chunk safety limit");
    }
    Ok(chunk_count)
}

fn ensure_root_metadata(header: &Header, root_key: &RootKeyMetadata) -> Result<()> {
    if header.root_key_id != root_key.id || header.root_key_epoch != root_key.epoch {
        bail!("root key ID or epoch does not match this archive");
    }
    Ok(())
}

fn ensure_expected_root(
    root_key: &RootKeyMetadata,
    expected_id: Option<&str>,
    expected_epoch: Option<u32>,
) -> Result<()> {
    if let Some(expected_id) = expected_id {
        let expected_id = parse_root_key_id(expected_id)?;
        if root_key.id != expected_id {
            bail!(
                "selected root key ID {} does not match expected ID {}",
                root_key_id_hex(&root_key.id),
                root_key_id_hex(&expected_id)
            );
        }
    }
    if let Some(expected_epoch) = expected_epoch
        && root_key.epoch != expected_epoch
    {
        bail!(
            "selected root key epoch {} does not match expected epoch {expected_epoch}",
            root_key.epoch
        );
    }
    Ok(())
}

fn read_u32<R: Read>(r: &mut R) -> Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_be_bytes(b))
}

struct Cursor<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Cursor<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.p.checked_add(n).is_none_or(|e| e > self.b.len()) {
            bail!("truncated header");
        }
        let out = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(out)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn at_end(&self) -> bool {
        self.p == self.b.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashSet,
        io,
        sync::atomic::{AtomicU64, Ordering},
    };

    static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Result<Self> {
            let sequence = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("pqbackup-test-{}-{sequence}", std::process::id()));
            fs::create_dir(&path)?;
            Ok(Self(path))
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct VectorData {
        archive: Vec<u8>,
        header: Vec<u8>,
        metadata_ciphertext: Vec<u8>,
        wrapped_dek: Vec<u8>,
        framed_ciphertext: Vec<u8>,
    }

    fn test_bytes<const N: usize>(start: u8) -> [u8; N] {
        std::array::from_fn(|i| start.wrapping_add(i as u8))
    }

    fn build_deterministic_vector(filename: &str, plaintext: &[u8], chunk_size: u32) -> VectorData {
        let seed = test_bytes::<MLKEM_SEED_LEN>(0x00);
        let dk = DecapsulationKey::new_from_slice(&seed).unwrap();
        let encapsulation_randomness = ml_kem::B32::try_from(&test_bytes::<32>(0x40)[..]).unwrap();
        let (kem_ct, shared_secret) = dk
            .encapsulation_key()
            .encapsulate_deterministic(&encapsulation_randomness);

        let root_id = test_bytes::<ROOT_KEY_ID_LEN>(0x60);
        let root_secret = test_bytes::<ROOT_SECRET_LEN>(0x70);
        let hkdf_salt = test_bytes::<32>(0x90);
        let data_nonce_prefix = test_bytes::<8>(0xb0);
        let wrap_nonce = test_bytes::<12>(0xc0);
        let metadata_nonce = test_bytes::<12>(0xd0);
        let dek = test_bytes::<DEK_LEN>(0xe0);
        let epoch = 0x0102_0304;

        let kek = derive_kek(shared_secret.as_slice(), &root_secret, &hkdf_salt).unwrap();
        let metadata_aad = encode_metadata_aad(
            chunk_size,
            plaintext.len() as u64,
            &root_id,
            epoch,
            &hkdf_salt,
            &data_nonce_prefix,
            &wrap_nonce,
            &metadata_nonce,
            kem_ct.as_slice(),
        )
        .unwrap();
        let cipher = Aes256Gcm::new_from_slice(kek.as_ref()).unwrap();
        let metadata_ciphertext = cipher
            .encrypt(
                &aes_nonce(&metadata_nonce),
                Payload {
                    msg: filename.as_bytes(),
                    aad: &metadata_aad,
                },
            )
            .unwrap();
        let wrap_aad = encode_wrap_aad(
            chunk_size,
            plaintext.len() as u64,
            &root_id,
            epoch,
            &hkdf_salt,
            &data_nonce_prefix,
            &wrap_nonce,
            &metadata_nonce,
            kem_ct.as_slice(),
            &metadata_ciphertext,
        )
        .unwrap();
        let wrapped_dek = cipher
            .encrypt(
                &aes_nonce(&wrap_nonce),
                Payload {
                    msg: &dek,
                    aad: &wrap_aad,
                },
            )
            .unwrap();
        let header = encode_header(&Header {
            chunk_size,
            original_len: plaintext.len() as u64,
            root_key_id: root_id,
            root_key_epoch: epoch,
            hkdf_salt,
            data_nonce_prefix,
            wrap_nonce,
            metadata_nonce,
            kem_ciphertext: kem_ct.as_slice().to_vec(),
            encrypted_filename: metadata_ciphertext.clone(),
            wrapped_dek: wrapped_dek.clone(),
        })
        .unwrap();
        let header_hash = Sha384::digest(&header);
        let data_cipher = Aes256Gcm::new_from_slice(&dek).unwrap();
        let mut framed_ciphertext = Vec::new();
        if plaintext.is_empty() {
            write_encrypted_chunk(
                &mut framed_ciphertext,
                &data_cipher,
                &header_hash,
                &data_nonce_prefix,
                0,
                true,
                &[],
            )
            .unwrap();
        } else {
            let chunks = plaintext.chunks(chunk_size as usize);
            let count = chunks.len();
            for (index, chunk) in chunks.enumerate() {
                write_encrypted_chunk(
                    &mut framed_ciphertext,
                    &data_cipher,
                    &header_hash,
                    &data_nonce_prefix,
                    index as u32,
                    index + 1 == count,
                    chunk,
                )
                .unwrap();
            }
        }
        let mut archive = Vec::new();
        archive.extend_from_slice(&(header.len() as u32).to_be_bytes());
        archive.extend_from_slice(&header);
        archive.extend_from_slice(&framed_ciphertext);
        VectorData {
            archive,
            header,
            metadata_ciphertext,
            wrapped_dek,
            framed_ciphertext,
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn fixture_hex(path_contents: &str) -> Vec<u8> {
        let compact: String = path_contents
            .lines()
            .filter(|line| !line.starts_with('#'))
            .collect();
        assert_eq!(compact.len() % 2, 0);
        (0..compact.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&compact[i..i + 2], 16).unwrap())
            .collect()
    }

    fn digest_hex<D: Digest + Default>(bytes: &[u8]) -> String {
        hex(&D::digest(bytes))
    }

    fn write_test_keys(dir: &Path) -> Result<(PathBuf, PathBuf, PathBuf)> {
        let (dk, ek) = MlKem1024::generate_keypair();
        let seed = dk
            .to_seed()
            .ok_or_else(|| anyhow!("test key did not retain a seed"))?;
        let public_path = dir.join("test.mlkem1024.pub");
        let secret_path = dir.join("test.mlkem1024.seed");
        let root_path = dir.join("test.root.key");
        write_new_file(&public_path, ek.to_bytes().as_slice(), false)?;
        write_new_file(&secret_path, seed.as_slice(), true)?;
        let root = RootKey {
            id: test_bytes::<ROOT_KEY_ID_LEN>(0x20),
            epoch: 7,
            secret: Zeroizing::new(test_bytes::<ROOT_SECRET_LEN>(0x40)),
        };
        write_new_file(&root_path, &encode_root_key(&root), true)?;
        Ok((public_path, secret_path, root_path))
    }

    fn write_test_signing_keys(
        dir: &Path,
        name: &str,
        id: [u8; SIGNER_KEY_ID_LEN],
        epoch: u32,
        seed_start: u8,
    ) -> Result<(PathBuf, PathBuf)> {
        let secret = SigningSecret {
            id,
            epoch,
            seed: Zeroizing::new(test_bytes::<MLDSA_SEED_LEN>(seed_start)),
        };
        let public_encoded = signing_key_from_secret(&secret).verifying_key().encode();
        let public = SigningPublic {
            id,
            epoch,
            encoded: public_encoded.as_slice().try_into().unwrap(),
        };
        let public_path = dir.join(format!("{name}.mldsa87.pub"));
        let secret_path = dir.join(format!("{name}.mldsa87.seed"));
        write_new_file(&public_path, &encode_signing_public(&public), false)?;
        write_new_file(&secret_path, &encode_signing_secret(&secret), true)?;
        Ok((public_path, secret_path))
    }

    #[test]
    fn deterministic_phase1_vectors_match_fixtures() {
        assert_eq!(
            fixture_hex(include_str!("../test-vectors/mlkem-seed.hex")),
            test_bytes::<MLKEM_SEED_LEN>(0x00)
        );
        let cases: Vec<(&str, String, Vec<u8>, u32)> = vec![
            ("empty", "empty.txt".into(), vec![], 16),
            (
                "one-chunk",
                "backup.txt".into(),
                b"pqbackup vector one\n".to_vec(),
                64,
            ),
            ("multi-chunk", "multi.bin".into(), (0u8..40).collect(), 13),
            (
                "unicode",
                "café-数据.txt".into(),
                b"unicode filename\n".to_vec(),
                64,
            ),
            (
                "max-filename",
                format!("{}x", "a".repeat(MAX_FILENAME_LEN - 1)),
                b"max name\n".to_vec(),
                64,
            ),
        ];
        let mut records = Vec::new();
        for (name, filename, plaintext, chunk_size) in cases {
            let v = build_deterministic_vector(&filename, &plaintext, chunk_size);
            records.push(format!(
                "{name}|{}|{}|{}|{}|{}|{}|{}|{}",
                plaintext.len(),
                chunk_size,
                digest_hex::<sha2::Sha256>(&plaintext),
                digest_hex::<Sha384>(&v.header),
                digest_hex::<Sha384>(&v.metadata_ciphertext),
                digest_hex::<Sha384>(&v.wrapped_dek),
                digest_hex::<Sha384>(&v.archive),
                digest_hex::<Sha384>(&v.framed_ciphertext)
            ));
            if name == "one-chunk" {
                let expected_hex: String = include_str!("../test-vectors/one-chunk.pqbk.hex")
                    .lines()
                    .filter(|line| !line.starts_with('#'))
                    .collect();
                assert_eq!(hex(&v.archive), expected_hex);
            }
        }
        let expected: Vec<&str> = include_str!("../test-vectors/checksums.txt")
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .collect();
        assert_eq!(records.as_slice(), expected.as_slice());
    }

    #[test]
    fn deterministic_phase5_provenance_vector_matches_fixture() {
        let archive = fixture_hex(include_str!("../test-vectors/one-chunk.pqbk.hex"));
        let signer_id = test_bytes::<SIGNER_KEY_ID_LEN>(0x81);
        let secret = SigningSecret {
            id: signer_id,
            epoch: 0x0102_0304,
            seed: Zeroizing::new(test_bytes::<MLDSA_SEED_LEN>(0xa0)),
        };
        let signing_key = signing_key_from_secret(&secret);
        let public = signing_key.verifying_key().encode();
        let statement = encode_provenance_statement(&signer_id, secret.epoch, archive.len() as u64);
        let signature: MlDsaSignature<MlDsa87> = signing_key
            .try_sign_digest(|digest| {
                digest.update(PROVENANCE_DOMAIN);
                digest.update(&archive);
                digest.update(&statement);
                Ok(())
            })
            .unwrap();
        let signature = signature.encode();
        let mut signed_archive = archive;
        signed_archive.extend_from_slice(&statement);
        signed_archive.extend_from_slice(signature.as_slice());
        let records = [
            format!("public-sha256|{}", sha256_hex(public.as_slice())),
            format!("statement-sha256|{}", sha256_hex(&statement)),
            format!("signature-sha256|{}", sha256_hex(signature.as_slice())),
            format!("signed-archive-sha256|{}", sha256_hex(&signed_archive)),
        ];
        let expected: Vec<String> = include_str!("../test-vectors/provenance-checksums.txt")
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .map(str::to_owned)
            .collect();
        assert_eq!(records.as_slice(), expected.as_slice());
    }

    #[test]
    fn root_key_round_trip_preserves_id_epoch_and_secret() {
        let root = RootKey {
            id: test_bytes::<ROOT_KEY_ID_LEN>(0x60),
            epoch: 0x0102_0304,
            secret: Zeroizing::new(test_bytes::<ROOT_SECRET_LEN>(0x70)),
        };
        let bytes = encode_root_key(&root);
        assert_eq!(
            *bytes,
            fixture_hex(include_str!("../test-vectors/root-key.hex"))
        );
        assert_eq!(&bytes[..8], ROOT_MAGIC);
        assert_eq!(
            u32::from_be_bytes(bytes[26..30].try_into().unwrap()),
            0x0102_0304
        );
        assert_eq!(&bytes[30..], &test_bytes::<ROOT_SECRET_LEN>(0x70));
    }

    #[test]
    fn file_provider_preserves_metadata_and_v2_kek_derivation() {
        let id = test_bytes::<ROOT_KEY_ID_LEN>(0x10);
        let secret = test_bytes::<ROOT_SECRET_LEN>(0x30);
        let shared = test_bytes::<32>(0x50);
        let salt = test_bytes::<32>(0x70);
        let expected = derive_kek(&shared, &secret, &salt).unwrap();
        let provider = FileRootSecretProvider {
            root: RootKey {
                id,
                epoch: 12,
                secret: Zeroizing::new(secret),
            },
        };
        let metadata = provider.metadata();
        assert_eq!(metadata.id, id);
        assert_eq!(metadata.epoch, 12);
        assert_eq!(
            *provider.derive_archive_kek(&shared, &salt).unwrap(),
            *expected
        );
    }

    #[test]
    fn metadata_aad_binds_root_id_and_epoch() {
        let kem = vec![0x42; MLKEM1024_CT_LEN];
        let a = encode_metadata_aad(
            4096,
            12,
            &[1; ROOT_KEY_ID_LEN],
            1,
            &[2; 32],
            &[3; 8],
            &[4; 12],
            &[5; 12],
            &kem,
        )
        .unwrap();
        let b = encode_metadata_aad(
            4096,
            12,
            &[1; ROOT_KEY_ID_LEN],
            2,
            &[2; 32],
            &[3; 8],
            &[4; 12],
            &[5; 12],
            &kem,
        )
        .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn root_key_id_requires_exact_hex() {
        assert!(parse_root_key_id("00112233445566778899aabbccddeeff").is_ok());
        assert!(parse_root_key_id("0011").is_err());
        assert!(parse_root_key_id("g0112233445566778899aabbccddeeff").is_err());
    }

    #[test]
    fn structural_negative_vectors_are_rejected() {
        let archive = fixture_hex(include_str!("../test-vectors/one-chunk.pqbk.hex"));
        let header_len = u32::from_be_bytes(archive[..4].try_into().unwrap()) as usize;
        let header = &archive[4..4 + header_len];
        assert!(decode_header(header).is_ok());

        for offset in [0usize, 8, 10, 12, 14] {
            let mut malformed = header.to_vec();
            malformed[offset] ^= 1;
            assert!(decode_header(&malformed).is_err(), "offset {offset}");
        }

        let mut zero_chunk = header.to_vec();
        zero_chunk[16..20].copy_from_slice(&0u32.to_be_bytes());
        assert!(decode_header(&zero_chunk).is_err());

        let mut trailing_header_byte = header.to_vec();
        trailing_header_byte.push(0);
        assert!(decode_header(&trailing_header_byte).is_err());
    }

    #[test]
    fn header_encoding_round_trips_canonical_vectors() {
        for (filename, plaintext, chunk_size) in [
            ("empty.txt", &b""[..], 16),
            ("backup.txt", &b"round trip"[..], 4),
            ("café-数据.txt", &b"unicode"[..], 64),
        ] {
            let vector = build_deterministic_vector(filename, plaintext, chunk_size);
            let decoded = decode_header(&vector.header).unwrap();
            assert_eq!(encode_header(&decoded).unwrap(), vector.header);
        }
    }

    #[test]
    fn archive_geometry_enforces_size_and_chunk_limits() {
        assert_eq!(validate_archive_geometry(0, MAX_CHUNK).unwrap(), 1);
        assert_eq!(
            validate_archive_geometry(MAX_PLAINTEXT_LEN, MAX_CHUNK).unwrap(),
            MAX_PLAINTEXT_LEN / u64::from(MAX_CHUNK)
        );
        assert!(validate_archive_geometry(MAX_PLAINTEXT_LEN + 1, MAX_CHUNK).is_err());
        assert!(validate_archive_geometry(MAX_DATA_CHUNKS, 1).is_ok());
        assert!(validate_archive_geometry(MAX_DATA_CHUNKS + 1, 1).is_err());
        assert!(validate_archive_geometry(1, 0).is_err());
        assert!(validate_archive_geometry(1, MAX_CHUNK + 1).is_err());
    }

    #[test]
    fn data_nonces_are_unique_at_supported_boundaries() {
        let prefix = [0xa5; 8];
        let indices = [
            0,
            1,
            2,
            MAX_DATA_CHUNKS as u32 - 2,
            MAX_DATA_CHUNKS as u32 - 1,
        ];
        let nonces: HashSet<[u8; 12]> = indices
            .into_iter()
            .map(|index| chunk_nonce(&prefix, index))
            .collect();
        assert_eq!(nonces.len(), indices.len());
        assert_eq!(&chunk_nonce(&prefix, 0)[..8], &prefix);
    }

    #[test]
    fn filename_validation_blocks_path_escape_without_normalizing_unicode() {
        for invalid in ["", ".", "..", "a/b", "/absolute", "nul\0name"] {
            assert!(validate_filename(invalid).is_err(), "{invalid:?}");
        }
        assert!(validate_filename("café-数据.txt").is_ok());
        #[cfg(unix)]
        assert!(validate_filename("backslash\\is-a-name-on-unix").is_ok());
    }

    #[test]
    fn end_to_end_empty_and_multi_chunk_archives() -> Result<()> {
        let dir = TestDir::new()?;
        let (public, secret, root) = write_test_keys(&dir.0)?;

        for (name, contents, chunk_size) in [
            ("empty.txt", Vec::new(), 16),
            ("multi.bin", (0u8..40).collect(), 13),
        ] {
            let input = dir.0.join(name);
            let archive = dir.0.join(format!("{name}.pqbk"));
            let restored = dir.0.join(format!("restored-{name}"));
            write_new_file(&input, &contents, false)?;
            seal(
                &input,
                Some(&archive),
                &public,
                &root,
                chunk_size,
                None,
                None,
            )?;
            verify_archive(&archive, &secret, &root)?;
            open_archive(&archive, Some(&restored), &secret, &root)?;
            assert_eq!(fs::read(&restored)?, contents);

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(fs::metadata(&restored)?.permissions().mode() & 0o777, 0o600);
            }
        }
        Ok(())
    }

    #[test]
    fn modified_truncated_and_wrong_key_archives_fail_closed() -> Result<()> {
        let dir = TestDir::new()?;
        let (public, secret, root) = write_test_keys(&dir.0)?;
        let input = dir.0.join("input.bin");
        let archive = dir.0.join("input.pqbk");
        write_new_file(&input, &(0u8..64).collect::<Vec<_>>(), false)?;
        seal(&input, Some(&archive), &public, &root, 13, None, None)?;

        let original = fs::read(&archive)?;
        let header_len = u32::from_be_bytes(original[..4].try_into().unwrap()) as usize;
        for (case, bytes) in [
            ("header", {
                let mut value = original.clone();
                value[4 + 48] ^= 1;
                value
            }),
            ("frame", {
                let mut value = original.clone();
                value[4 + header_len + 9] ^= 1;
                value
            }),
            ("truncated", original[..original.len() - 1].to_vec()),
        ] {
            let malformed = dir.0.join(format!("{case}.pqbk"));
            fs::write(&malformed, bytes)?;
            assert!(
                verify_archive(&malformed, &secret, &root).is_err(),
                "{case}"
            );
        }

        let other_root = dir.0.join("other.root.key");
        let root_key = RootKey {
            id: test_bytes::<ROOT_KEY_ID_LEN>(0x21),
            epoch: 7,
            secret: Zeroizing::new(test_bytes::<ROOT_SECRET_LEN>(0x41)),
        };
        write_new_file(&other_root, &encode_root_key(&root_key), true)?;
        assert!(verify_archive(&archive, &secret, &other_root).is_err());

        let other_keys = dir.0.join("other-keys");
        fs::create_dir(&other_keys)?;
        let (_, other_secret, _) = write_test_keys(&other_keys)?;
        assert!(verify_archive(&archive, &other_secret, &root).is_err());
        Ok(())
    }

    #[test]
    fn restore_collision_and_authentication_failure_leave_no_partial_output() -> Result<()> {
        let dir = TestDir::new()?;
        let (public, secret, root) = write_test_keys(&dir.0)?;
        let input = dir.0.join("input.txt");
        let archive = dir.0.join("input.pqbk");
        let output = dir.0.join("output.txt");
        write_new_file(&input, b"authenticated contents", false)?;
        seal(&input, Some(&archive), &public, &root, 8, None, None)?;

        write_new_file(&output, b"do not replace", false)?;
        assert!(open_archive(&archive, Some(&output), &secret, &root).is_err());
        assert_eq!(fs::read(&output)?, b"do not replace");
        fs::remove_file(&output)?;

        let mut damaged = fs::read(&archive)?;
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        let damaged_path = dir.0.join("damaged.pqbk");
        fs::write(&damaged_path, damaged)?;
        assert!(open_archive(&damaged_path, Some(&output), &secret, &root).is_err());
        assert!(!output.exists());
        assert!(fs::read_dir(&dir.0)?.all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("output.txt.")
        }));
        Ok(())
    }

    #[test]
    fn publication_race_never_replaces_destination() -> Result<()> {
        let dir = TestDir::new()?;
        let temp_path = dir.0.join(".pending.tmp");
        let destination = dir.0.join("destination");
        write_new_file(&temp_path, b"new", false)?;
        let pending = TemporaryFile::new(temp_path.clone());
        write_new_file(&destination, b"existing", false)?;
        assert!(pending.commit(&destination).is_err());
        assert_eq!(fs::read(&destination)?, b"existing");
        assert!(!temp_path.exists());
        Ok(())
    }

    #[test]
    fn expected_root_assertions_prevent_wrong_epoch_sealing() -> Result<()> {
        let dir = TestDir::new()?;
        let (public, _, root_path) = write_test_keys(&dir.0)?;
        let root = FileRootSecretProvider::open(&root_path)?.metadata();
        let id = root_key_id_hex(&root.id);
        assert!(ensure_expected_root(&root, Some(&id), Some(root.epoch)).is_ok());
        assert!(
            ensure_expected_root(
                &root,
                Some("ffffffffffffffffffffffffffffffff"),
                Some(root.epoch)
            )
            .is_err()
        );
        assert!(ensure_expected_root(&root, Some(&id), Some(root.epoch + 1)).is_err());

        let input = dir.0.join("input.txt");
        let rejected = dir.0.join("rejected.pqbk");
        write_new_file(&input, b"root assertion", false)?;
        assert!(
            seal(
                &input,
                Some(&rejected),
                &public,
                &root_path,
                64,
                Some(&id),
                Some(root.epoch + 1),
            )
            .is_err()
        );
        assert!(!rejected.exists());
        Ok(())
    }

    #[test]
    fn key_info_validates_all_supported_material_types() -> Result<()> {
        let dir = TestDir::new()?;
        let (public, secret, root) = write_test_keys(&dir.0)?;
        let input = dir.0.join("input.txt");
        let archive = dir.0.join("input.pqbk");
        write_new_file(&input, b"key info", false)?;
        seal(&input, Some(&archive), &public, &root, 64, None, None)?;

        key_info(&root, KeyFileKind::Root)?;
        key_info(&public, KeyFileKind::KemPublic)?;
        key_info(&secret, KeyFileKind::KemSeed)?;
        key_info(&archive, KeyFileKind::Archive)?;
        assert!(key_info(&root, KeyFileKind::KemSeed).is_err());

        let public_bytes = fs::read(&public)?;
        let seed_bytes = Zeroizing::new(fs::read(&secret)?);
        let dk = DecapsulationKey::new_from_slice(seed_bytes.as_slice()).unwrap();
        assert_eq!(
            sha256_hex(&public_bytes),
            sha256_hex(dk.encapsulation_key().to_bytes().as_slice())
        );
        Ok(())
    }

    #[test]
    fn inventory_records_no_secrets_and_locates_archive_epoch() -> Result<()> {
        let dir = TestDir::new()?;
        let (public, secret, root_path) = write_test_keys(&dir.0)?;
        let inventory_path = dir.0.join("inventory.toml");
        inventory_init(&inventory_path)?;
        inventory_add(
            &inventory_path,
            &root_path,
            Some("annual archive root"),
            &[
                "offline safe copy A".to_owned(),
                "offsite safe copy B".to_owned(),
            ],
            RootKeyStatus::Active,
        )?;
        inventory_check(&inventory_path)?;
        inventory_list(&inventory_path)?;

        let inventory_text = fs::read_to_string(&inventory_path)?;
        assert!(inventory_text.contains(INVENTORY_FORMAT));
        assert!(!inventory_text.contains("secret"));
        let inventory = read_inventory(&inventory_path)?;
        assert_eq!(inventory.root_keys.len(), 1);
        assert_eq!(inventory.root_keys[0].custody.len(), 2);

        let input = dir.0.join("input.txt");
        let archive = dir.0.join("input.pqbk");
        write_new_file(&input, b"inventory locate", false)?;
        seal(&input, Some(&archive), &public, &root_path, 64, None, None)?;
        inventory_locate(&inventory_path, &archive)?;

        let root = read_root_key(&root_path)?;
        inventory_set_status(
            &inventory_path,
            &root_key_id_hex(&root.id),
            root.epoch,
            RootKeyStatus::Retired,
        )?;
        assert_eq!(
            read_inventory(&inventory_path)?.root_keys[0].status,
            RootKeyStatus::Retired
        );
        assert!(
            inventory_set_status(
                &inventory_path,
                &root_key_id_hex(&root.id),
                root.epoch,
                RootKeyStatus::Active,
            )
            .is_err()
        );
        inventory_set_status(
            &inventory_path,
            &root_key_id_hex(&root.id),
            root.epoch,
            RootKeyStatus::Compromised,
        )?;
        assert!(
            inventory_set_status(
                &inventory_path,
                &root_key_id_hex(&root.id),
                root.epoch,
                RootKeyStatus::Retired,
            )
            .is_err()
        );
        assert!(
            inventory_add(
                &inventory_path,
                &root_path,
                None,
                &["duplicate".to_owned()],
                RootKeyStatus::Active,
            )
            .is_err()
        );

        let seed_copy = dir.0.join("seed-copy");
        let root_copy = dir.0.join("root-copy");
        fs::copy(&secret, &seed_copy)?;
        fs::copy(&root_path, &root_copy)?;
        verify_archive(&archive, &secret, &root_path)?;
        verify_archive(&archive, &seed_copy, &root_copy)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&inventory_path)?.permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(fs::metadata(&secret)?.permissions().mode() & 0o777, 0o600);
            assert_eq!(
                fs::metadata(&root_path)?.permissions().mode() & 0o777,
                0o600
            );
        }
        Ok(())
    }

    #[test]
    fn malformed_inventory_is_rejected() -> Result<()> {
        let dir = TestDir::new()?;
        let path = dir.0.join("inventory.toml");
        fs::write(
            &path,
            r#"format = "PQINVENTORY01"

[[root_keys]]
id = "00112233445566778899AABBCCDDEEFF"
epoch = 1
status = "active"
custody = ["safe"]
"#,
        )?;
        assert!(read_inventory(&path).is_err());

        fs::write(
            &path,
            r#"format = "PQINVENTORY01"
unexpected = "field"
"#,
        )?;
        assert!(read_inventory(&path).is_err());

        let oversized = "x".repeat(MAX_INVENTORY_LEN as usize + 1);
        assert!(decode_inventory(&oversized).is_err());
        assert!(validate_single_line("safe\u{202e}txt", 200, "label").is_err());
        Ok(())
    }

    #[test]
    fn bounded_reads_stop_at_limit_and_reject_truncation() -> Result<()> {
        let mut source = std::io::repeat(0x42);
        assert!(read_bounded(&mut source, 62, "test").is_err());
        struct CountRead {
            count: usize,
        }
        impl Read for CountRead {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                buf.fill(0x42);
                self.count += buf.len();
                Ok(buf.len())
            }
        }
        let mut counted = CountRead { count: 0 };
        assert!(read_bounded(&mut counted, 64, "seed").is_err());
        assert_eq!(counted.count, 65);
        assert!(read_bounded(std::io::empty(), usize::MAX, "overflow").is_err());
        let dir = TestDir::new()?;
        let path = dir.0.join("key");
        write_new_file(&path, b"short", true)?;
        assert!(read_exact_sized_secret(&path, 64, "seed").is_err());
        fs::write(&path, [0u8; 65])?;
        assert!(read_exact_sized_secret(&path, 64, "seed").is_err());
        fs::write(&path, [0u8; 64])?;
        assert_eq!(read_exact_sized_secret(&path, 64, "seed")?.len(), 64);
        // The size cap applies to the stream even if a pre-read metadata length is stale.
        let opened = open_material(&path, true, "seed")?;
        fs::write(&path, [0u8; 65])?;
        assert!(read_bounded(opened, 64, "seed").is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn material_reads_enforce_file_type_symlinks_and_secret_permissions() -> Result<()> {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = TestDir::new()?;
        let path = dir.0.join("seed");
        write_new_file(&path, &[0u8; 64], true)?;
        for mode in [0o600, 0o400] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
            read_exact_sized_secret(&path, 64, "seed")?;
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        assert!(read_exact_sized_secret(&path, 64, "seed").is_err());
        read_exact_sized(&path, 64, "public material")?;
        assert!(validate_secret_permissions(1000, 0o600, 1001).is_err());
        assert!(validate_secret_permissions(1000, 0o640, 1000).is_err());
        assert!(read_exact_sized(&dir.0, 64, "directory").is_err());
        let link = dir.0.join("link");
        symlink(&path, &link)?;
        assert!(read_exact_sized(&link, 64, "symlink").is_err());
        assert!(read_inventory(&link).is_err());
        assert!(read_signer_policy(&link).is_err());
        let fifo = dir.0.join("fifo");
        let fifo_name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes())?;
        // SAFETY: the C string is NUL-terminated and valid for this call.
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        assert!(open_material(&fifo, true, "FIFO").is_err());
        assert!(open_material(Path::new("/dev/null"), false, "device").is_err());
        Ok(())
    }

    #[test]
    fn staged_write_failures_remove_only_owned_files() -> Result<()> {
        let dir = TestDir::new()?;
        let output = dir.0.join("key");
        for stage in ["stage.write", "stage.flush", "stage.sync", "publish.link"] {
            IO_FAILURE.with(|failure| failure.set(Some(stage)));
            assert!(write_new_file(&output, b"secret", true).is_err(), "{stage}");
            assert!(!output.exists());
            assert_eq!(fs::read_dir(&dir.0)?.count(), 0, "{stage}");
        }
        assert!(
            stage_file_with(&output, true, |file| {
                file.write_all(b"partially written secret")?;
                bail!("simulated disk-full after partial write")
            })
            .is_err()
        );
        assert_eq!(fs::read_dir(&dir.0)?.count(), 0);
        write_new_file(&output, b"existing", true)?;
        assert!(write_new_file(&output, b"replacement", true).is_err());
        assert_eq!(fs::read(&output)?, b"existing");
        assert_eq!(fs::read_dir(&dir.0)?.count(), 1);
        Ok(())
    }

    #[test]
    fn publication_errors_report_already_visible_output() -> Result<()> {
        for stage in ["directory.sync", "publish.unlink"] {
            let dir = TestDir::new()?;
            let output = dir.0.join("output");
            let pending = stage_file(&output, b"complete", true)?;
            IO_FAILURE.with(|failure| failure.set(Some(stage)));
            let error = pending.commit(&output).unwrap_err();
            assert!(error.to_string().contains("was published"));
            assert_eq!(fs::read(&output)?, b"complete");
            assert_eq!(fs::read_dir(&dir.0)?.count(), 1);
        }
        let dir = TestDir::new()?;
        let output = dir.0.join("policy");
        write_new_file(&output, b"original", true)?;
        let pending = stage_file(&output, b"updated", true)?;
        IO_FAILURE.with(|failure| failure.set(Some("publish.rename")));
        assert!(pending.replace(&output).is_err());
        assert_eq!(fs::read(&output)?, b"original");
        let pending = stage_file(&output, b"updated", true)?;
        IO_FAILURE.with(|failure| failure.set(Some("directory.sync")));
        let error = pending.replace(&output).unwrap_err();
        assert!(error.to_string().contains("was replaced"));
        assert_eq!(fs::read(&output)?, b"updated");
        Ok(())
    }

    #[test]
    fn key_pair_failure_preserves_complete_secret_and_existing_files() -> Result<()> {
        let dir = TestDir::new()?;
        let public = dir.0.join("public");
        let secret = dir.0.join("secret");
        IO_FAILURE.with(|failure| failure.set(Some("pair.public")));
        let error = write_key_pair(&public, b"public", &secret, b"secret").unwrap_err();
        assert!(error.to_string().contains("secret retained"));
        assert_eq!(fs::read(&secret)?, b"secret");
        assert!(!public.exists());
        assert_eq!(fs::read_dir(&dir.0)?.count(), 1);
        assert!(write_key_pair(&public, b"public", &secret, b"new").is_err());
        assert!(!public.exists());
        assert_eq!(fs::read(&secret)?, b"secret");
        assert!(keygen_kem(&dir.0, "../escaped").is_err());
        assert!(keygen_signing(&dir.0, "../escaped", None, 0).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn new_key_directories_are_private_and_existing_permissions_are_preserved() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new()?;
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o750))?;
        let nested = dir.0.join("new/nested");
        keygen_kem(&nested, "archive")?;
        for path in [dir.0.join("new"), nested.clone()] {
            assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o700);
        }
        assert_eq!(fs::metadata(&dir.0)?.permissions().mode() & 0o777, 0o750);
        read_exact_sized_secret(
            &nested.join("archive.mlkem1024.seed"),
            MLKEM_SEED_LEN,
            "seed",
        )?;
        read_exact_sized(
            &nested.join("archive.mlkem1024.pub"),
            MLKEM1024_PK_LEN,
            "public",
        )?;
        assert!(create_key_directory(&nested.join("archive.mlkem1024.pub/child")).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn interrupted_private_temporary_file_requires_explicit_cleanup() -> Result<()> {
        use std::os::unix::{fs::PermissionsExt, process::ExitStatusExt};
        const CHILD_PATH: &str = "PQBACKUP_TEST_INTERRUPTED_OUTPUT";
        if let Some(path) = std::env::var_os(CHILD_PATH) {
            let (_pending, mut file) = TemporaryFile::create(Path::new(&path), true)?;
            file.write_all(b"authenticated prefix; archive not yet complete")?;
            file.sync_all()?;
            // SAFETY: terminate only this deliberately spawned unit-test process.
            unsafe {
                libc::kill(libc::getpid(), libc::SIGKILL);
            }
            unreachable!("SIGKILL should terminate the child");
        }
        let dir = TestDir::new()?;
        let output = dir.0.join("restore");
        let child = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "tests::interrupted_private_temporary_file_requires_explicit_cleanup",
                "--nocapture",
            ])
            .env(CHILD_PATH, &output)
            .output()?;
        assert_eq!(child.status.signal(), Some(libc::SIGKILL));
        assert!(!output.exists());
        let entries = fs::read_dir(&dir.0)?.collect::<std::io::Result<Vec<_>>>()?;
        assert_eq!(entries.len(), 1);
        let leftover = entries[0].path();
        assert_eq!(fs::metadata(&leftover)?.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            fs::read(&leftover)?,
            b"authenticated prefix; archive not yet complete"
        );
        fs::remove_file(&leftover)?;
        sync_parent(&leftover)?;
        Ok(())
    }

    struct ProvenanceFixture {
        dir: TestDir,
        signed: PathBuf,
        public: PathBuf,
        signing_secret: PathBuf,
        policy: PathBuf,
        seed: PathBuf,
        root: PathBuf,
    }

    impl ProvenanceFixture {
        fn new() -> Result<Self> {
            let dir = TestDir::new()?;
            let unsigned = dir.0.join("unsigned.pqbk");
            let signed = dir.0.join("signed.pqbk");
            fs::write(
                &unsigned,
                build_deterministic_vector("restored.txt", b"phase one content", 4).archive,
            )?;
            let (public, signing_secret) =
                write_test_signing_keys(&dir.0, "signer", test_bytes::<16>(0x81), 7, 0xb0)?;
            let policy = dir.0.join("policy.toml");
            signer_policy_init(&policy)?;
            signer_policy_add(&policy, &public, "Phase one signer", SignerStatus::Trusted)?;
            sign_archive(&unsigned, Some(&signed), &signing_secret)?;
            let seed = dir.0.join("seed");
            let root = dir.0.join("root");
            write_new_file(&seed, &test_bytes::<MLKEM_SEED_LEN>(0), true)?;
            write_new_file(
                &root,
                &encode_root_key(&RootKey {
                    id: test_bytes::<16>(0x60),
                    epoch: 0x0102_0304,
                    secret: Zeroizing::new(test_bytes::<32>(0x70)),
                }),
                true,
            )?;
            Ok(Self {
                dir,
                signed,
                public,
                signing_secret,
                policy,
                seed,
                root,
            })
        }

        fn options(&self) -> ProvenanceOptions {
            ProvenanceOptions {
                require_provenance: true,
                signer_public_key: Some(self.public.clone()),
                signer_policy: Some(self.policy.clone()),
                allow_retired: false,
            }
        }

        fn rejects(&self, archive: &Path, options: &ProvenanceOptions) -> Result<()> {
            let output = self.dir.0.join("must-not-exist");
            let before = fs::read_dir(&self.dir.0)?.count();
            assert!(verify_archive_with_policy(archive, &self.seed, &self.root, options).is_err());
            assert!(
                open_archive_with_policy(archive, Some(&output), &self.seed, &self.root, options)
                    .is_err()
            );
            assert!(!output.exists());
            assert_eq!(
                fs::read_dir(&self.dir.0)?.count(),
                before,
                "failure left a temporary plaintext file"
            );
            Ok(())
        }
    }

    #[test]
    fn required_provenance_cli_rejects_incomplete_or_implicit_policy() {
        for command in ["open", "verify"] {
            let base = [
                "pqbackup",
                command,
                "a.pqbk",
                "--secret-key",
                "seed",
                "--root-secret",
                "root",
            ];
            for invalid in [
                vec!["--require-provenance"],
                vec!["--signer-public-key", "pub"],
                vec!["--signer-policy", "policy"],
                vec!["--allow-retired"],
                vec!["--require-provenance", "--signer-public-key", "pub"],
                vec!["--require-provenance", "--signer-policy", "policy"],
                vec!["--signer-public-key", "pub", "--signer-policy", "policy"],
            ] {
                assert!(Cli::try_parse_from(base.into_iter().chain(invalid)).is_err());
            }
            assert!(Cli::try_parse_from(base).is_ok());
            assert!(
                Cli::try_parse_from(base.into_iter().chain([
                    "--require-provenance",
                    "--signer-public-key",
                    "pub",
                    "--signer-policy",
                    "policy",
                    "--allow-retired",
                ]))
                .is_ok()
            );
        }
    }

    #[test]
    fn required_provenance_enforces_signature_and_content_before_publication() -> Result<()> {
        let f = ProvenanceFixture::new()?;
        let options = f.options();
        let output = f.dir.0.join("restored");
        open_archive_with_policy(&f.signed, Some(&output), &f.seed, &f.root, &options)?;
        assert_eq!(fs::read(output)?, b"phase one content");
        verify_archive_with_policy(&f.signed, &f.seed, &f.root, &options)?;
        let bytes = fs::read(&f.signed)?;
        let envelope_len = scan_archive_layout(&f.signed)?.envelope_len as usize;
        let damaged = f.dir.0.join("damaged.pqbk");
        let mut bad_signature = bytes.clone();
        *bad_signature.last_mut().unwrap() ^= 1;
        let mut extra = bytes.clone();
        extra.push(0);
        for invalid in [
            bytes[..envelope_len].to_vec(),
            bytes[..bytes.len() - 1].to_vec(),
            bad_signature,
            extra,
        ] {
            fs::write(&damaged, invalid)?;
            f.rejects(&damaged, &options)?;
        }
        // A valid signature over damaged ciphertext is insufficient for combined verification.
        let mut bad_content = bytes[..envelope_len].to_vec();
        bad_content[envelope_len - 1] ^= 1;
        fs::write(&damaged, bad_content)?;
        let signed_bad_content = f.dir.0.join("signed-bad-content.pqbk");
        sign_archive(&damaged, Some(&signed_bad_content), &f.signing_secret)?;
        verify_provenance(&signed_bad_content, &f.public, &f.policy, false)?;
        f.rejects(&signed_bad_content, &options)?;
        // Existing unsigned recovery remains supported without the new policy.
        fs::write(&damaged, &bytes[..envelope_len])?;
        verify_archive(&damaged, &f.seed, &f.root)?;
        Ok(())
    }

    #[test]
    fn required_provenance_enforces_identity_fingerprint_and_lifecycle() -> Result<()> {
        let f = ProvenanceFixture::new()?;
        let mut options = f.options();
        let (other, _) =
            write_test_signing_keys(&f.dir.0, "other", test_bytes::<16>(0x81), 7, 0xc0)?;
        options.signer_public_key = Some(other);
        f.rejects(&f.signed, &options)?;
        options = f.options();
        let original_policy = fs::read_to_string(&f.policy)?;
        let mut policy = read_signer_policy(&f.policy)?;
        policy.signers[0].public_sha256 = "00".repeat(32);
        fs::write(&f.policy, encode_signer_policy(&policy)?)?;
        f.rejects(&f.signed, &options)?;
        policy.signers.clear();
        fs::write(&f.policy, encode_signer_policy(&policy)?)?;
        f.rejects(&f.signed, &options)?;
        fs::write(&f.policy, original_policy)?;
        let id = signer_key_id_hex(&test_bytes::<16>(0x81));
        signer_policy_set_status(&f.policy, &id, 7, SignerStatus::Retired)?;
        f.rejects(&f.signed, &options)?;
        options.allow_retired = true;
        verify_archive_with_policy(&f.signed, &f.seed, &f.root, &options)?;
        let output = f.dir.0.join("historical-restored");
        open_archive_with_policy(&f.signed, Some(&output), &f.seed, &f.root, &options)?;
        assert_eq!(fs::read(output)?, b"phase one content");
        signer_policy_set_status(&f.policy, &id, 7, SignerStatus::Revoked)?;
        f.rejects(&f.signed, &options)?;
        Ok(())
    }

    #[test]
    fn provenance_result_hash_is_bound_to_consumed_bytes_after_path_change() -> Result<()> {
        for replace in [false, true] {
            let f = ProvenanceFixture::new()?;
            let original = fs::read(&f.signed)?;
            let (_, verified) = verify_provenance_reader(
                archive_input(&f.signed)?,
                &f.public,
                &f.policy,
                false,
                |reader| {
                    let layout = scan_archive_reader(reader)?;
                    // Deterministic hook at the former scan/verify/hash boundary.
                    if replace {
                        fs::rename(&f.signed, f.dir.0.join("original"))?;
                    }
                    fs::write(&f.signed, b"unverified replacement")?;
                    Ok(((), layout.provenance))
                },
            )?;
            assert_eq!(verified.archive_sha256, sha256_hex(&original));
            assert_eq!(verified.archive_len, original.len() as u64);
            assert_eq!(verified.identity, "Phase one signer");
            assert_eq!(verified.signer_epoch, 7);
            assert_ne!(verified.archive_sha256, sha256_file(&f.signed)?);
        }
        Ok(())
    }

    struct HookedRead<F> {
        file: File,
        hook: Option<F>,
        consumed: usize,
    }

    impl<F: FnOnce() -> std::io::Result<()>> Read for HookedRead<F> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.consumed >= 128
                && let Some(hook) = self.hook.take()
            {
                hook()?;
            }
            let max = buf.len().min(128);
            let n = self.file.read(&mut buf[..max])?;
            self.consumed += n;
            Ok(n)
        }
    }

    #[test]
    fn combined_stream_verification_handles_replacement_and_in_place_mutation() -> Result<()> {
        for replace in [false, true] {
            let f = ProvenanceFixture::new()?;
            let original = fs::read(&f.signed)?;
            let mut modified = original.clone();
            let end = scan_archive_layout(&f.signed)?.envelope_len as usize;
            modified[end - 1] ^= 1;
            let source = HookedRead {
                file: File::open(&f.signed)?,
                consumed: 0,
                hook: Some(|| {
                    if replace {
                        fs::rename(&f.signed, f.dir.0.join("original"))?;
                    }
                    fs::write(&f.signed, modified)
                }),
            };
            let mut plaintext = Vec::new();
            let result = verify_provenance_reader(source, &f.public, &f.policy, false, |reader| {
                let mut decoded = decrypt_archive_reader(reader, &f.seed, &f.root, &mut plaintext)?;
                Ok(((), decoded.provenance.take()))
            });
            if replace {
                let (_, verified) = result?;
                assert_eq!(verified.archive_sha256, sha256_hex(&original));
                assert_eq!(plaintext, b"phase one content");
            } else {
                assert!(result.is_err(), "mutation of unread ciphertext must fail");
            }
        }
        Ok(())
    }

    #[test]
    fn signing_key_files_and_phase5_cli_round_trip() -> Result<()> {
        let dir = TestDir::new()?;
        let id = test_bytes::<SIGNER_KEY_ID_LEN>(0x91);
        let (public_path, secret_path) = write_test_signing_keys(&dir.0, "signer", id, 42, 0xa1)?;
        let public = read_signing_public(&public_path)?;
        let secret = read_signing_secret(&secret_path)?;
        assert_eq!(public.id, id);
        assert_eq!(public.epoch, 42);
        assert_eq!(secret.id, id);
        assert_eq!(secret.epoch, 42);
        assert_eq!(
            signing_key_from_secret(&secret)
                .verifying_key()
                .encode()
                .as_slice(),
            public.encoded
        );
        key_info(&public_path, KeyFileKind::SigningPublic)?;
        key_info(&secret_path, KeyFileKind::SigningSeed)?;

        let cli = Cli::try_parse_from([
            "pqbackup",
            "provenance-verify",
            "archive.pqbk",
            "--public-key",
            "signer.pub",
            "--policy",
            "signers.toml",
            "--allow-retired",
        ])?;
        match cli.command {
            Command::ProvenanceVerify { allow_retired, .. } => assert!(allow_retired),
            _ => panic!("unexpected command"),
        }
        Ok(())
    }

    #[test]
    fn provenance_authenticates_complete_envelope_and_explicit_identity() -> Result<()> {
        let dir = TestDir::new()?;
        let unsigned = dir.0.join("unsigned.pqbk");
        let signed = dir.0.join("signed.pqbk");
        fs::write(
            &unsigned,
            build_deterministic_vector("backup.txt", b"signed payload", 64).archive,
        )?;
        let signer_id = test_bytes::<SIGNER_KEY_ID_LEN>(0x81);
        let (public, secret) = write_test_signing_keys(&dir.0, "trusted", signer_id, 7, 0xb0)?;
        let policy = dir.0.join("signers.toml");
        signer_policy_init(&policy)?;
        signer_policy_add(
            &policy,
            &public,
            "Test release signer",
            SignerStatus::Trusted,
        )?;

        sign_archive(&unsigned, Some(&signed), &secret)?;
        let layout = scan_archive_layout(&signed)?;
        let provenance = layout.provenance.as_ref().unwrap();
        assert_eq!(provenance.signer_key_id, signer_id);
        assert_eq!(provenance.signer_key_epoch, 7);
        assert_eq!(provenance.signed_len, layout.envelope_len);
        verify_provenance(&signed, &public, &policy, false)?;

        let recovery_seed = dir.0.join("vector.mlkem1024.seed");
        let recovery_root = dir.0.join("vector.root.key");
        write_new_file(&recovery_seed, &test_bytes::<MLKEM_SEED_LEN>(0x00), true)?;
        write_new_file(
            &recovery_root,
            &encode_root_key(&RootKey {
                id: test_bytes::<ROOT_KEY_ID_LEN>(0x60),
                epoch: 0x0102_0304,
                secret: Zeroizing::new(test_bytes::<ROOT_SECRET_LEN>(0x70)),
            }),
            true,
        )?;
        verify_archive(&signed, &recovery_seed, &recovery_root)?;

        let replay = dir.0.join("replayed-copy.pqbk");
        fs::copy(&signed, &replay)?;
        verify_provenance(&replay, &public, &policy, false)?;

        let mut modified = fs::read(&signed)?;
        modified[layout.envelope_len as usize - 1] ^= 1;
        let modified_path = dir.0.join("modified.pqbk");
        fs::write(&modified_path, modified)?;
        assert!(verify_provenance(&modified_path, &public, &policy, false).is_err());

        let (substitute_public, _) =
            write_test_signing_keys(&dir.0, "substitute", signer_id, 7, 0xc0)?;
        assert!(verify_provenance(&signed, &substitute_public, &policy, false).is_err());
        assert!(sign_archive(&signed, None, &secret).is_err());
        Ok(())
    }

    #[test]
    fn signer_lifecycle_rejects_retired_by_default_and_always_rejects_revoked() -> Result<()> {
        let dir = TestDir::new()?;
        let unsigned = dir.0.join("unsigned.pqbk");
        let signed = dir.0.join("signed.pqbk");
        fs::write(
            &unsigned,
            build_deterministic_vector("history.txt", b"historical", 64).archive,
        )?;
        let signer_id = test_bytes::<SIGNER_KEY_ID_LEN>(0x71);
        let (public, secret) = write_test_signing_keys(&dir.0, "historical", signer_id, 3, 0xd0)?;
        let policy = dir.0.join("signers.toml");
        signer_policy_init(&policy)?;
        signer_policy_add(&policy, &public, "Historical signer", SignerStatus::Trusted)?;
        sign_archive(&unsigned, Some(&signed), &secret)?;

        let id = signer_key_id_hex(&signer_id);
        signer_policy_set_status(&policy, &id, 3, SignerStatus::Retired)?;
        assert!(verify_provenance(&signed, &public, &policy, false).is_err());
        verify_provenance(&signed, &public, &policy, true)?;

        signer_policy_set_status(&policy, &id, 3, SignerStatus::Revoked)?;
        assert!(verify_provenance(&signed, &public, &policy, false).is_err());
        assert!(verify_provenance(&signed, &public, &policy, true).is_err());
        assert!(
            signer_policy_set_status(&policy, &id, 3, SignerStatus::Trusted).is_err(),
            "revocation must be irreversible for an existing epoch"
        );
        Ok(())
    }

    #[test]
    fn malformed_ml_kem_public_key_is_rejected() -> Result<()> {
        let dir = TestDir::new()?;
        let invalid = dir.0.join("invalid.mlkem1024.pub");
        fs::write(&invalid, vec![0xff; MLKEM1024_PK_LEN])?;
        assert!(key_info(&invalid, KeyFileKind::KemPublic).is_err());
        Ok(())
    }

    #[test]
    fn lifecycle_transition_matrices_are_monotonic() {
        for (current, next, permitted) in [
            (RootKeyStatus::Active, RootKeyStatus::Active, true),
            (RootKeyStatus::Active, RootKeyStatus::Retired, true),
            (RootKeyStatus::Active, RootKeyStatus::Compromised, true),
            (RootKeyStatus::Active, RootKeyStatus::Destroyed, true),
            (RootKeyStatus::Retired, RootKeyStatus::Active, false),
            (RootKeyStatus::Retired, RootKeyStatus::Retired, true),
            (RootKeyStatus::Retired, RootKeyStatus::Compromised, true),
            (RootKeyStatus::Retired, RootKeyStatus::Destroyed, true),
            (RootKeyStatus::Compromised, RootKeyStatus::Active, false),
            (RootKeyStatus::Compromised, RootKeyStatus::Retired, false),
            (RootKeyStatus::Compromised, RootKeyStatus::Compromised, true),
            (RootKeyStatus::Compromised, RootKeyStatus::Destroyed, true),
            (RootKeyStatus::Destroyed, RootKeyStatus::Active, false),
            (RootKeyStatus::Destroyed, RootKeyStatus::Retired, false),
            (RootKeyStatus::Destroyed, RootKeyStatus::Compromised, false),
            (RootKeyStatus::Destroyed, RootKeyStatus::Destroyed, true),
        ] {
            assert_eq!(
                ensure_root_key_status_transition(current, next).is_ok(),
                permitted,
                "unexpected root-key transition result for {current} -> {next}"
            );
        }

        for (current, next, permitted) in [
            (SignerStatus::Trusted, SignerStatus::Trusted, true),
            (SignerStatus::Trusted, SignerStatus::Retired, true),
            (SignerStatus::Trusted, SignerStatus::Revoked, true),
            (SignerStatus::Retired, SignerStatus::Trusted, false),
            (SignerStatus::Retired, SignerStatus::Retired, true),
            (SignerStatus::Retired, SignerStatus::Revoked, true),
            (SignerStatus::Revoked, SignerStatus::Trusted, false),
            (SignerStatus::Revoked, SignerStatus::Retired, false),
            (SignerStatus::Revoked, SignerStatus::Revoked, true),
        ] {
            assert_eq!(
                ensure_signer_status_transition(current, next).is_ok(),
                permitted,
                "unexpected signer transition result for {current} -> {next}"
            );
        }
    }

    #[test]
    fn older_signed_archive_remains_valid_without_an_external_rollback_catalog() -> Result<()> {
        let dir = TestDir::new()?;
        let signer_id = test_bytes::<SIGNER_KEY_ID_LEN>(0x51);
        let (public, secret) = write_test_signing_keys(&dir.0, "catalog", signer_id, 9, 0xf0)?;
        let policy = dir.0.join("signers.toml");
        signer_policy_init(&policy)?;
        signer_policy_add(
            &policy,
            &public,
            "Catalog test signer",
            SignerStatus::Trusted,
        )?;

        for (name, payload) in [
            ("older", &b"generation 1"[..]),
            ("newer", &b"generation 2"[..]),
        ] {
            let unsigned = dir.0.join(format!("{name}.unsigned.pqbk"));
            let signed = dir.0.join(format!("{name}.pqbk"));
            fs::write(
                &unsigned,
                build_deterministic_vector("snapshot.txt", payload, 64).archive,
            )?;
            sign_archive(&unsigned, Some(&signed), &secret)?;
            verify_provenance(&signed, &public, &policy, false)?;
        }
        Ok(())
    }

    #[test]
    fn provenance_parser_rejects_truncation_and_extra_trailers() -> Result<()> {
        let dir = TestDir::new()?;
        let unsigned = dir.0.join("unsigned.pqbk");
        let signed = dir.0.join("signed.pqbk");
        fs::write(
            &unsigned,
            build_deterministic_vector("parser.txt", b"parser", 64).archive,
        )?;
        let (_, secret) = write_test_signing_keys(
            &dir.0,
            "parser",
            test_bytes::<SIGNER_KEY_ID_LEN>(0x61),
            1,
            0xe0,
        )?;
        sign_archive(&unsigned, Some(&signed), &secret)?;
        let bytes = fs::read(&signed)?;
        let envelope_len = scan_archive_layout(&signed)?.envelope_len as usize;

        for (name, length) in [
            ("statement", envelope_len + 1),
            ("signature", bytes.len() - 1),
        ] {
            let path = dir.0.join(format!("truncated-{name}.pqbk"));
            fs::write(&path, &bytes[..length])?;
            assert!(scan_archive_layout(&path).is_err(), "{name}");
        }
        let extra = dir.0.join("extra.pqbk");
        let mut extra_bytes = bytes;
        extra_bytes.push(0);
        fs::write(&extra, extra_bytes)?;
        assert!(scan_archive_layout(&extra).is_err());
        Ok(())
    }

    #[test]
    fn malformed_signer_policy_is_rejected() -> Result<()> {
        let duplicate = r#"format = "PQSIGNERS01"

[[signers]]
id = "00112233445566778899aabbccddeeff"
epoch = 1
identity = "Release signer"
status = "trusted"
public_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"

[[signers]]
id = "00112233445566778899aabbccddeeff"
epoch = 1
identity = "Substitute signer"
status = "trusted"
public_sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
"#;
        assert!(decode_signer_policy(duplicate).is_err());
        assert!(decode_signer_policy(&"x".repeat(MAX_SIGNER_POLICY_LEN as usize + 1)).is_err());
        Ok(())
    }

    #[test]
    fn phase3_cli_accepts_repeated_custody_and_root_assertions() {
        let cli = Cli::try_parse_from([
            "pqbackup",
            "inventory",
            "add",
            "inventory.toml",
            "--root-secret",
            "root.key",
            "--custody",
            "copy A",
            "--custody",
            "copy B",
        ])
        .unwrap();
        match cli.command {
            Command::Inventory {
                command: InventoryCommand::Add { custody, .. },
            } => assert_eq!(custody, ["copy A", "copy B"]),
            _ => panic!("unexpected command"),
        }

        let cli = Cli::try_parse_from([
            "pqbackup",
            "seal",
            "input",
            "--public-key",
            "public",
            "--root-secret",
            "root",
            "--expect-root-key-id",
            "00112233445566778899aabbccddeeff",
            "--expect-root-key-epoch",
            "2027",
        ])
        .unwrap();
        match cli.command {
            Command::Seal {
                expect_root_key_id,
                expect_root_key_epoch,
                ..
            } => {
                assert_eq!(
                    expect_root_key_id.as_deref(),
                    Some("00112233445566778899aabbccddeeff")
                );
                assert_eq!(expect_root_key_epoch, Some(2027));
            }
            _ => panic!("unexpected command"),
        }
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "simulated full disk",
            ))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn output_write_failure_is_reported() -> Result<()> {
        let dir = TestDir::new()?;
        let vector = build_deterministic_vector("backup.txt", b"payload", 64);
        let archive = dir.0.join("vector.pqbk");
        let seed_path = dir.0.join("seed");
        let root_path = dir.0.join("root");
        fs::write(&archive, vector.archive)?;
        write_new_file(&seed_path, &test_bytes::<MLKEM_SEED_LEN>(0x00), true)?;
        let root = RootKey {
            id: test_bytes::<ROOT_KEY_ID_LEN>(0x60),
            epoch: 0x0102_0304,
            secret: Zeroizing::new(test_bytes::<ROOT_SECRET_LEN>(0x70)),
        };
        write_new_file(&root_path, &encode_root_key(&root), true)?;
        assert!(decrypt_archive_to(&archive, &seed_path, &root_path, &mut FailingWriter).is_err());
        Ok(())
    }

    #[test]
    fn header_parser_rejects_every_truncated_prefix_without_panicking() {
        let archive = fixture_hex(include_str!("../test-vectors/one-chunk.pqbk.hex"));
        let header_len = u32::from_be_bytes(archive[..4].try_into().unwrap()) as usize;
        let header = &archive[4..4 + header_len];
        for length in 0..header.len() {
            assert!(decode_header(&header[..length]).is_err(), "length {length}");
        }

        let mut excessive_length = header.to_vec();
        excessive_length[20..28].copy_from_slice(&(MAX_PLAINTEXT_LEN + 1).to_be_bytes());
        assert!(decode_header(&excessive_length).is_err());
    }
}
