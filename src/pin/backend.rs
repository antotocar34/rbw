use std::collections::HashMap;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use anyhow::{anyhow, Context};
use argon2::password_hash::SaltString;
use serde::{Deserialize, Serialize};
use crate::config::Config;
use crate::pin::backend_age::{AgePinBackend, SUPPORTED_AGE_PLUGINS};
use crate::pin::crypto::{Argon2Params, WrappedKeys};

#[derive(Serialize, Deserialize, clap::ValueEnum, Clone, Debug)]
pub enum Backend {
    Age,
    OSKeyring
    // Keyring(OsKeyringPinBackend)
}

impl PinBackend for Backend {
    fn retrieve_local_secret(&self, config: &Config) -> anyhow::Result<crate::locked::Vec> {
        match self {
            Backend::Age => AgePinBackend.retrieve_local_secret(config),
            Backend::OSKeyring => todo!()
        }
    }

    fn store_local_secret(&self, kek: &crate::locked::Vec, config: &Config) -> anyhow::Result<()> {
        match self {
            Backend::Age => AgePinBackend.store_local_secret(kek, config),
            Backend::OSKeyring => todo!()
        }
    }

    fn clear_local_secret(&self) -> anyhow::Result<()> {
        match self {
            Backend::Age => AgePinBackend.clear_local_secret(),
            Backend::OSKeyring => todo!()
        }
    }

    fn identifier(&self) -> String {
        match self {
            Backend::Age => AgePinBackend.identifier(),
            Backend::OSKeyring => todo!()
        }
    }
}

pub trait PinBackend {
    fn retrieve_local_secret(&self, config: &Config) -> anyhow::Result<crate::locked::Vec>;

    fn store_local_secret(&self, kek: &crate::locked::Vec, config: &Config) -> anyhow::Result<()>;

    fn clear_local_secret(&self) -> anyhow::Result<()>;

    fn identifier(&self) -> String;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PinBackendConfig {
    pub enable_pin: bool,
    #[serde(flatten)]
    pub kdf_params: Option<Argon2Params>,

    // OsKeyring
    pub local_secret_keyring_entry_name: Option<String>,

    // Age
    pub age_identity_file_path: Option<PathBuf>,
}

impl PinBackendConfig {
    pub fn new() -> Self {
        Self {
            enable_pin: false,
            kdf_params: Some(Argon2Params::new()),
            local_secret_keyring_entry_name: None,
            age_identity_file_path: None
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct PinState {
    wrapped_keys: WrappedKeys,
    wrapped_org_keys: HashMap<String,WrappedKeys>,
    salt: String,
    kdf_params: Argon2Params,
    pub empty_pin: bool,
    pub backend: crate::pin::backend::Backend
}

impl PinState {
    pub fn new(
        wrapped_keys: WrappedKeys,
        wrapped_org_keys: HashMap<String, WrappedKeys>,
        salt: SaltString,
        kdf_params: Argon2Params,
        empty_pin: bool,
        backend: Backend
    ) -> anyhow::Result<Self> {
        let slf = Self {
            wrapped_keys,
            wrapped_org_keys,
            salt: salt.to_string(),
            kdf_params,
            empty_pin,
            backend
        };
        Ok(slf)
    }

    pub fn unpack(&self) -> anyhow::Result<(WrappedKeys, HashMap<String, WrappedKeys>, SaltString, Argon2Params, bool)> {
        Ok((
            self.wrapped_keys.clone(),
            self.wrapped_org_keys.clone(),
            {
                match SaltString::from_b64(self.salt.as_str()) {
                    Ok(salt) => salt,
                    Err(e) => anyhow::bail!("Error deserializing salt: {}", e)
                }
            },
            self.kdf_params.clone(),
            self.empty_pin
        ))
    }

    pub fn read_from_file(path: PathBuf) -> anyhow::Result<Self> {
        let file = std::fs::File::open(path).context("Could not open pin state file")?;
        let reader = std::io::BufReader::new(file);
        serde_json::from_reader(reader).map_err(|e| anyhow!(e))
    }

    pub fn write_to_file(&self) -> anyhow::Result<()> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .mode(0o600)
            .write(true)
            .truncate(true)
            .open(crate::dirs::pin_state_file())?;

        let mut writer = std::io::BufWriter::new(file);
        serde_json::to_writer(&mut writer, self)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        Ok(())
    }

    // async pub fn write_to_file_async(&self) -> anyhow::Result<()> {
    //
    // }
}

