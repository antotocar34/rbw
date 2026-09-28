pub mod age;
pub mod keyring;

use crate::locked::Vec;
use crate::pin::crypto::{Argon2Params, WrappedKey};
use anyhow::{anyhow, Context as _};
use argon2::password_hash::SaltString;
use serde::{Deserialize, Serialize};
use std::io::Write as _;
use std::path::{Path, PathBuf};

#[derive(
    Serialize, Deserialize, clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq,
)]
pub enum Backend {
    Age,
    OSKeyring,
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Age => "age",
            Self::OSKeyring => "os-keyring",
        })
    }
}

/// Where the PIN state lives on disk. Tests point this at a temporary
/// directory so they never touch the real cache directory.
#[derive(Clone, Debug)]
pub struct Paths {
    pub state_file: PathBuf,
    pub age_secret_file: PathBuf,
}

impl Paths {
    pub fn new() -> Self {
        Self {
            state_file: crate::dirs::pin_state_file(),
            age_secret_file: crate::dirs::pin_age_wrapped_local_secret_file(),
        }
    }
}

impl Default for Paths {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend {
    /// Check that the backend can actually store the local secret, before
    /// anything is written.
    pub fn check_available(
        self,
        config: &PinBackendConfig,
    ) -> anyhow::Result<()> {
        match self {
            Self::Age => age::validate(config.age_identity_file()?),
            Self::OSKeyring => keyring::check_available(),
        }
    }

    pub fn store_local_secret<C: ::age::Callbacks>(
        self,
        local_secret: &Vec,
        config: &PinBackendConfig,
        paths: &Paths,
        callbacks: C,
    ) -> anyhow::Result<()> {
        match self {
            Self::Age => age::store(
                local_secret,
                config.age_identity_file()?,
                &paths.age_secret_file,
                callbacks,
            ),
            Self::OSKeyring => keyring::store(local_secret),
        }
    }

    pub fn retrieve_local_secret<C: ::age::Callbacks>(
        self,
        config: &PinBackendConfig,
        paths: &Paths,
        callbacks: C,
    ) -> anyhow::Result<Vec> {
        match self {
            Self::Age => age::retrieve(
                config.age_identity_file()?,
                &paths.age_secret_file,
                callbacks,
            ),
            Self::OSKeyring => keyring::retrieve(),
        }
    }

    /// Remove the local secret. Succeeds if it is already gone.
    pub fn clear_local_secret(self, paths: &Paths) -> anyhow::Result<()> {
        match self {
            Self::Age => age::clear(&paths.age_secret_file),
            Self::OSKeyring => keyring::clear(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct PinBackendConfig {
    #[serde(default)]
    pub enable_pin: bool,
    #[serde(flatten)]
    pub kdf_params: Argon2Params,
    #[serde(
        rename = "age_identity_file_path",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub age_identity_file: Option<PathBuf>,
}

impl PinBackendConfig {
    fn age_identity_file(&self) -> anyhow::Result<&Path> {
        self.age_identity_file.as_deref().ok_or_else(|| {
            anyhow!(
                "age_identity_file_path is not set (use `rbw config set \
                 age_identity_file_path <path>`)"
            )
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct PinState {
    wrapped_key: WrappedKey,
    salt: String,
    kdf_params: Argon2Params,
    empty_pin: bool,
    backend: Backend,
}

impl PinState {
    pub fn new(
        wrapped_key: WrappedKey,
        salt: &SaltString,
        kdf_params: Argon2Params,
        empty_pin: bool,
        backend: Backend,
    ) -> Self {
        Self {
            wrapped_key,
            salt: salt.to_string(),
            kdf_params,
            empty_pin,
            backend,
        }
    }

    pub fn wrapped_key(&self) -> &WrappedKey {
        &self.wrapped_key
    }

    pub fn salt(&self) -> anyhow::Result<SaltString> {
        SaltString::from_b64(&self.salt)
            .map_err(|e| anyhow!("invalid salt in PIN state: {e}"))
    }

    pub fn kdf_params(&self) -> &Argon2Params {
        &self.kdf_params
    }

    pub fn empty_pin(&self) -> bool {
        self.empty_pin
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    pub fn read_from_file(path: &Path) -> anyhow::Result<Self> {
        let file = std::fs::File::open(path)
            .context("could not open PIN state file")?;
        serde_json::from_reader(std::io::BufReader::new(file)).context(
            "could not parse PIN state file (run `rbw pin set` again)",
        )
    }

    pub fn write_to_file(&self, path: &Path) -> anyhow::Result<()> {
        write_private_file(path, &serde_json::to_vec(self)?)
    }
}

/// Atomically replace `path` with `contents`, readable only by the user.
pub(crate) fn write_private_file(
    path: &Path,
    contents: &[u8],
) -> anyhow::Result<()> {
    let parent = path.parent().context("path has no parent directory")?;
    std::fs::create_dir_all(parent)?;

    // NamedTempFile is created with mode 0600
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(contents)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// Remove a file, treating "already gone" as success.
pub(crate) fn remove_file_if_exists(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e)
            .with_context(|| format!("failed to remove {}", path.display())),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_config_partial_fields_use_defaults() {
        let config: PinBackendConfig = serde_json::from_str(
            r#"{"enable_pin": true, "argon2_memory": 1024}"#,
        )
        .unwrap();
        assert!(config.enable_pin);
        assert_eq!(
            config.kdf_params,
            Argon2Params {
                memory: 1024,
                ..Argon2Params::default()
            }
        );
        assert!(config.age_identity_file.is_none());

        let config: PinBackendConfig = serde_json::from_str("{}").unwrap();
        assert!(!config.enable_pin);
        assert_eq!(config.kdf_params, Argon2Params::default());
    }
}
