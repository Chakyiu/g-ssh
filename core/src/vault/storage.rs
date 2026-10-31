use std::{
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use super::{legacy_vault_path, VAULT_FILE_NAME};
use crate::vault::error::VaultError;
use crate::vault::model::{
    serde_b64, AeadBlob, JsonAead, KdfParams, VaultFile, LEGACY_VAULT_VERSION, VAULT_VERSION,
};

const MAX_VAULT_SIZE: u64 = 64 * 1024 * 1024;

// Upper limits only: a damaged or planted file must not make Argon2 ask for
// terabytes of memory before the password is even checked.
const MAX_KDF_MEMORY_KIB: u32 = 1_048_576;
const MAX_KDF_PASSES: u32 = 10;
const MAX_KDF_LANES: u32 = 4;

/// Read first, so a file from a newer format is reported as such even when
/// the rest of its layout no longer matches [`VaultFile`].
#[derive(Deserialize)]
struct VaultFileVersion {
    version: u32,
}

#[derive(Serialize, Deserialize)]
struct JsonVaultFile {
    version: u32,
    #[serde(with = "serde_b64::array32")]
    kdf_salt: [u8; 32],
    kdf_params: KdfParams,
    enc_dek_by_password: JsonAead,
    enc_dek_by_recovery: JsonAead,
    enc_payload: JsonAead,
}

impl From<&VaultFile> for JsonVaultFile {
    fn from(vault: &VaultFile) -> Self {
        Self {
            version: vault.version,
            kdf_salt: vault.kdf_salt,
            kdf_params: vault.kdf_params.clone(),
            enc_dek_by_password: JsonAead::from(&vault.enc_dek_by_password),
            enc_dek_by_recovery: JsonAead::from(&vault.enc_dek_by_recovery),
            enc_payload: JsonAead::from(&vault.enc_payload),
        }
    }
}

impl From<JsonVaultFile> for VaultFile {
    fn from(vault: JsonVaultFile) -> Self {
        Self {
            version: vault.version,
            kdf_salt: vault.kdf_salt,
            kdf_params: vault.kdf_params,
            enc_dek_by_password: AeadBlob::from(vault.enc_dek_by_password),
            enc_dek_by_recovery: AeadBlob::from(vault.enc_dek_by_recovery),
            enc_payload: AeadBlob::from(vault.enc_payload),
        }
    }
}

/// Where an unlock read the vault from. A legacy file is rewritten as JSON.
pub(super) struct OpenSource {
    pub source: PathBuf,
    pub file: VaultFile,
    /// The bytes were CBOR (`vault.bin`), not `vault.json`.
    pub is_legacy: bool,
}

#[cfg(test)]
pub(crate) fn read_vault(path: &Path) -> Result<VaultFile, VaultError> {
    let data = read_limited(path)?;
    let (file, is_legacy) = decode(&data)?;
    if is_legacy {
        return Err(VaultError::Corrupted(
            "expected the JSON vault, found the old binary vault".into(),
        ));
    }
    Ok(file)
}

/// The file at `requested`, or a sibling `vault.bin` when the JSON file is not
/// there yet. The old file is reported as legacy so the caller can rewrite it.
pub(super) fn open_source(requested: &Path) -> Result<OpenSource, VaultError> {
    if requested.exists() {
        let data = read_limited(requested)?;
        let (file, is_legacy) = decode(&data)?;
        return Ok(OpenSource {
            source: requested.to_path_buf(),
            file,
            is_legacy,
        });
    }
    if requested.file_name() == Some(std::ffi::OsStr::new(VAULT_FILE_NAME)) {
        if let Some(legacy) = legacy_vault_path(requested) {
            if legacy.exists() {
                let data = read_limited(&legacy)?;
                let (file, _) = decode(&data)?;
                return Ok(OpenSource {
                    source: legacy,
                    file,
                    is_legacy: true,
                });
            }
        }
    }
    read_limited(requested)?;
    Err(VaultError::Corrupted(
        "vault file vanished before it could be read".into(),
    ))
}

pub fn write_vault(path: &Path, vault: &VaultFile) -> Result<(), VaultError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut buf = serde_json::to_vec_pretty(&JsonVaultFile::from(vault))
        .map_err(|e| VaultError::Corrupted(format!("JSON encode: {e}")))?;
    buf.push(b'\n');
    write_atomic(path, &buf)
}

fn read_limited(path: &Path) -> Result<Vec<u8>, VaultError> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > MAX_VAULT_SIZE {
        return Err(VaultError::Corrupted(format!(
            "vault file is too large ({} bytes)",
            meta.len()
        )));
    }
    Ok(std::fs::read(path)?)
}

fn decode(data: &[u8]) -> Result<(VaultFile, bool), VaultError> {
    if is_json(data) {
        Ok((decode_json(data)?, false))
    } else {
        Ok((decode_cbor(data)?, true))
    }
}

fn is_json(data: &[u8]) -> bool {
    data.iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|byte| *byte == b'{')
}

fn decode_json(data: &[u8]) -> Result<VaultFile, VaultError> {
    let header: VaultFileVersion = serde_json::from_slice(data)
        .map_err(|e| VaultError::Corrupted(format!("JSON decode: {e}")))?;
    if header.version != VAULT_VERSION {
        return Err(VaultError::UnsupportedVersion(header.version));
    }
    let vault: JsonVaultFile = serde_json::from_slice(data)
        .map_err(|e| VaultError::Corrupted(format!("JSON decode: {e}")))?;
    check_kdf(&vault.kdf_params)?;
    Ok(VaultFile::from(vault))
}

fn decode_cbor(data: &[u8]) -> Result<VaultFile, VaultError> {
    let header: VaultFileVersion = ciborium::from_reader(data)
        .map_err(|e| VaultError::Corrupted(format!("CBOR decode: {e}")))?;
    if header.version != LEGACY_VAULT_VERSION {
        return Err(VaultError::UnsupportedVersion(header.version));
    }
    let vault: VaultFile = ciborium::from_reader(data)
        .map_err(|e| VaultError::Corrupted(format!("CBOR decode: {e}")))?;
    check_kdf(&vault.kdf_params)?;
    Ok(vault)
}

fn check_kdf(kdf: &KdfParams) -> Result<(), VaultError> {
    if kdf.m_cost > MAX_KDF_MEMORY_KIB || kdf.t_cost > MAX_KDF_PASSES || kdf.p_cost > MAX_KDF_LANES
    {
        return Err(VaultError::Corrupted("KDF cost is out of range".into()));
    }
    Ok(())
}

pub(super) fn tmp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

pub(super) fn write_atomic(path: &Path, data: &[u8]) -> Result<(), VaultError> {
    #[cfg(unix)]
    atomic_write_unix(path, data)?;
    #[cfg(windows)]
    atomic_write_windows(path, data)?;
    #[cfg(not(any(unix, windows)))]
    compile_error!("unsupported platform");
    Ok(())
}

#[cfg(unix)]
fn atomic_write_unix(path: &Path, data: &[u8]) -> Result<(), VaultError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    let tmp = tmp_path(path);

    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(data)?;
        file.flush()?;
        file.sync_all()?;
    }

    std::fs::rename(&tmp, path)?;

    // fsync the parent directory so the rename survives a crash. Best effort:
    // the file is in place, and some file systems (e.g. FAT) can't do this.
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(())
}

#[cfg(windows)]
fn atomic_write_windows(path: &Path, data: &[u8]) -> Result<(), VaultError> {
    use windows::core::HSTRING;
    use windows::Win32::Storage::FileSystem::ReplaceFileW;

    let tmp = tmp_path(path);

    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
    }

    if !path.exists() {
        // ReplaceFileW fails when the target does not exist yet
        return std::fs::rename(&tmp, path).map_err(VaultError::Io);
    }

    // ReplaceFileW preserves ACLs and attributes of the replaced file
    let target = HSTRING::from(path.as_os_str());
    let replacement = HSTRING::from(tmp.as_os_str());
    unsafe {
        ReplaceFileW(&target, &replacement, None, Default::default(), None, None)
            .map_err(|e| VaultError::Io(std::io::Error::other(e)))?;
    }

    Ok(())
}
