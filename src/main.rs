use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand, ValueEnum};
use hkdf::Hkdf;
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

struct DecryptedArchive {
    header: Header,
    original_name: String,
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

    fn commit(mut self, destination: &Path) -> Result<()> {
        // A hard link publishes the completed inode atomically and fails if the destination
        // appeared after our earlier collision check. This avoids rename's overwrite race.
        fs::hard_link(&self.path, destination).with_context(|| {
            format!(
                "publishing verified temporary output {} as {}",
                self.path.display(),
                destination.display()
            )
        })?;
        fs::remove_file(&self.path)
            .with_context(|| format!("removing temporary output {}", self.path.display()))?;
        self.committed = true;
        Ok(())
    }

    fn replace(mut self, destination: &Path) -> Result<()> {
        fs::rename(&self.path, destination).with_context(|| {
            format!(
                "replacing {} with temporary file {}",
                destination.display(),
                self.path.display()
            )
        })?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
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
    },

    /// Cryptographically verify the full archive without writing plaintext.
    Verify {
        input: PathBuf,
        #[arg(long)]
        secret_key: PathBuf,
        #[arg(long)]
        root_secret: PathBuf,
    },

    /// Display non-secret envelope metadata without decrypting.
    Inspect { input: PathBuf },

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

#[derive(Debug)]
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
        } => open_archive(&input, output.as_deref(), &secret_key, &root_secret),
        Command::Verify {
            input,
            secret_key,
            root_secret,
        } => verify_archive(&input, &secret_key, &root_secret),
        Command::Inspect { input } => inspect(&input),
        Command::KeyInfo { input, kind } => key_info(&input, kind),
        Command::Inventory { command } => inventory_command(command),
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
    let archive = out_dir.join("demo-backup.pqbk");
    let restored = restore_dir.join("demo-backup.txt");
    let public_key = keys_dir.join("demo.mlkem1024.pub");
    let secret_key = keys_dir.join("demo.mlkem1024.seed");
    let root_key = keys_dir.join("demo.root.key");
    let inventory = out_dir.join("root-key-inventory.toml");

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

    println!("\n5. Seal the sample backup.");
    seal(
        &input,
        Some(&archive),
        &public_key,
        &root_key,
        DEFAULT_CHUNK,
        None,
        None,
    )?;
    println!("\n6. Inspect public archive metadata; the filename stays encrypted.");
    inspect(&archive)?;
    println!("\n7. Locate the requested root-key custody record.");
    inventory_locate(&inventory, &archive)?;
    println!("\n8. Verify every encrypted chunk without restoring plaintext.");
    verify_archive(&archive, &secret_key, &root_key)?;
    println!("\n9. Restore the archive to a separate directory.");
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
    fs::create_dir_all(out_dir).with_context(|| format!("creating {}", out_dir.display()))?;

    let (dk, ek) = MlKem1024::generate_keypair();
    let seed = dk
        .to_seed()
        .ok_or_else(|| anyhow!("ML-KEM key generation did not retain a seed"))?;
    let public_bytes = ek.to_bytes();

    let pub_path = out_dir.join(format!("{name}.mlkem1024.pub"));
    let sec_path = out_dir.join(format!("{name}.mlkem1024.seed"));

    write_new_file(&pub_path, public_bytes.as_slice(), false)?;
    write_new_file(&sec_path, seed.as_slice(), true)?;

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
            let header = read_header_from_file(input)?;
            println!("file type       : PQBACK02 archive");
            println!("validation      : structurally valid header (unauthenticated)");
            println!("root key ID     : {}", root_key_id_hex(&header.root_key_id));
            println!("root key epoch  : {}", header.root_key_epoch);
            println!("filename        : encrypted");
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
    record.status = status;
    replace_inventory(path, &encode_inventory(&inventory)?)?;
    println!("Updated root key {canonical_id} epoch {root_key_epoch} to {status}.");
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
    let metadata = fs::metadata(path)
        .with_context(|| format!("reading inventory metadata from {}", path.display()))?;
    if !metadata.is_file() {
        bail!("inventory must be a regular file");
    }
    if metadata.len() > MAX_INVENTORY_LEN {
        bail!("inventory exceeds the {MAX_INVENTORY_LEN}-byte safety limit");
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading inventory {}", path.display()))?;
    decode_inventory(&text)
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
    let pending = TemporaryFile::new(temporary_output_path(path)?);
    let mut file = create_private_new(&pending.path)
        .with_context(|| format!("creating temporary inventory {}", pending.path.display()))?;
    file.write_all(encoded.as_bytes())?;
    file.sync_all()?;
    drop(file);
    pending.replace(path)
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

    let mut reader =
        BufReader::new(File::open(input).with_context(|| format!("opening {}", input.display()))?);
    if out_path.exists() {
        bail!(
            "refusing to overwrite existing output {}",
            out_path.display()
        );
    }
    let pending = TemporaryFile::new(temporary_output_path(&out_path)?);
    let mut writer = BufWriter::new(
        create_private_new(&pending.path)
            .with_context(|| format!("creating temporary output {}", pending.path.display()))?,
    );

    writer.write_all(&(header_bytes.len() as u32).to_be_bytes())?;
    writer.write_all(&header_bytes)?;

    let data_cipher =
        Aes256Gcm::new_from_slice(dek.as_ref()).map_err(|_| anyhow!("invalid DEK length"))?;

    let mut buf = vec![0u8; chunk_size as usize];
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

fn open_archive(
    input: &Path,
    output: Option<&Path>,
    secret_key_path: &Path,
    root_secret_path: &Path,
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
    let pending = TemporaryFile::new(temporary_output_path(temp_anchor)?);
    let file = create_private_new(&pending.path)
        .with_context(|| format!("creating temporary output {}", pending.path.display()))?;
    let mut writer = BufWriter::new(file);

    let decrypted = decrypt_archive_to(input, secret_key_path, root_secret_path, &mut writer)?;
    let out_path = requested_output.unwrap_or_else(|| PathBuf::from(decrypted.original_name));
    if out_path.exists() {
        bail!(
            "refusing to overwrite existing output {}",
            out_path.display()
        );
    }

    writer.flush()?;
    writer.get_ref().sync_all()?;
    drop(writer);
    pending.commit(&out_path)?;

    println!("Opened {} -> {}", input.display(), out_path.display());
    Ok(())
}

fn verify_archive(input: &Path, secret_key_path: &Path, root_secret_path: &Path) -> Result<()> {
    let mut sink = std::io::sink();
    let decrypted = decrypt_archive_to(input, secret_key_path, root_secret_path, &mut sink)?;
    println!(
        "Verified {}: authenticated {} bytes",
        input.display(),
        decrypted.header.original_len
    );
    Ok(())
}

fn decrypt_archive_to<W: Write>(
    input: &Path,
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

    let mut reader =
        BufReader::new(File::open(input).with_context(|| format!("opening {}", input.display()))?);

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

    let kek = root_provider.derive_archive_kek(shared_secret.as_slice(), &header.hkdf_salt)?;

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
    let original_name =
        String::from_utf8(original_name_bytes.to_vec()).context("invalid encrypted filename")?;
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

    let mut expected_index: u32 = 0;
    let mut total: u64 = 0;

    loop {
        if u64::from(expected_index) >= MAX_DATA_CHUNKS {
            bail!("archive exceeds the {MAX_DATA_CHUNKS}-chunk safety limit");
        }
        let frame = read_encrypted_frame(&mut reader, header.chunk_size)?
            .ok_or_else(|| anyhow!("archive truncated before authenticated final chunk"))?;

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

    let mut trailing = [0u8; 1];
    if reader.read(&mut trailing)? != 0 {
        bail!("unexpected trailing data after final chunk");
    }

    Ok(DecryptedArchive {
        header,
        original_name,
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
    let header = read_header_from_file(input)?;

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
    Ok(())
}

fn derive_kek(shared: &[u8], root: &[u8; ROOT_SECRET_LEN], salt: &[u8; 32]) -> Result<[u8; 32]> {
    // Fixed-length composition: 32-byte ML-KEM shared secret || 32-byte independent root secret.
    let mut ikm = [0u8; 64];
    if shared.len() != 32 {
        bail!("unexpected ML-KEM shared secret length");
    }
    ikm[..32].copy_from_slice(shared);
    ikm[32..].copy_from_slice(root);

    let hk = Hkdf::<Sha384>::new(Some(salt), &ikm);
    let mut kek = [0u8; 32];
    hk.expand(b"pqbackup/v2/archive-kek/aes-256-gcm", &mut kek)
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

fn write_new_file(path: &Path, data: &[u8], secret: bool) -> Result<()> {
    let mut f = if secret {
        create_private_new(path)?
    } else {
        create_new(path)?
    };
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

fn read_exact_sized(path: &Path, expected: usize, label: &str) -> Result<Vec<u8>> {
    let data =
        fs::read(path).with_context(|| format!("reading {label} from {}", path.display()))?;
    if data.len() != expected {
        bail!(
            "{label} must be exactly {expected} bytes; got {}",
            data.len()
        );
    }
    Ok(data)
}

fn read_exact_sized_secret(
    path: &Path,
    expected: usize,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let data = Zeroizing::new(
        fs::read(path).with_context(|| format!("reading {label} from {}", path.display()))?,
    );
    if data.len() != expected {
        bail!(
            "{label} must be exactly {expected} bytes; got {}",
            data.len()
        );
    }
    Ok(data)
}

fn encode_root_key(root: &RootKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 2 + ROOT_KEY_ID_LEN + 4 + ROOT_SECRET_LEN);
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
        let data = Zeroizing::new(
            fs::read(path)
                .with_context(|| format!("reading root secret from {}", path.display()))?,
        );
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
        Ok(Zeroizing::new(derive_kek(
            shared_secret,
            &self.root.secret,
            salt,
        )?))
    }
}

fn file_root_secret_provider(path: &Path) -> Result<Box<dyn RootSecretProvider>> {
    Ok(Box::new(FileRootSecretProvider::open(path)?))
}

#[cfg(test)]
fn read_root_key(path: &Path) -> Result<RootKey> {
    let data = Zeroizing::new(
        fs::read(path).with_context(|| format!("reading root secret from {}", path.display()))?,
    );
    decode_root_key(&data)
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
        let cipher = Aes256Gcm::new_from_slice(&kek).unwrap();
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
        assert_eq!(records, expected);
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
            bytes,
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
            expected
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
        fs::write(&seed_path, test_bytes::<MLKEM_SEED_LEN>(0x00))?;
        let root = RootKey {
            id: test_bytes::<ROOT_KEY_ID_LEN>(0x60),
            epoch: 0x0102_0304,
            secret: Zeroizing::new(test_bytes::<ROOT_SECRET_LEN>(0x70)),
        };
        fs::write(&root_path, encode_root_key(&root))?;
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
