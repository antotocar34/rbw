#![cfg(feature = "pin")]

mod age;
mod keyring;

use std::collections::HashMap;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use anyhow::{anyhow, Context};
use argon2::password_hash::SaltString;
use serde::{Deserialize, Serialize};
use crate::config::Config;
use crate::dirs;
use crate::pin::backend::age::{AgeConfig, AgePinBackend};
use crate::pin::backend::keyring::{KeyringConfig, KeyringPinBackend};
use crate::pin::cli::Pin;
use crate::pin::crypto::{Argon2Params, WrappedKey};

#[derive(Serialize, Deserialize, clap::ValueEnum, Clone, Debug)]
pub enum Backend {
    Age,
    OSKeyring
    // Keyring(OsKeyringPinBackend)
}

impl BackendConfig for PinBackendConfig { }

pub trait PinBackend {
    type Config: BackendConfig;
    fn retrieve_local_secret(&self, config: &Self::Config) -> anyhow::Result<crate::locked::Vec>;

    fn store_local_secret(&self, kek: &crate::locked::Vec, config: &Self::Config) -> anyhow::Result<()>;

    fn clear_local_secret(&self) -> anyhow::Result<()>;
}

impl PinBackend for Backend {
    type Config = PinBackendConfig;
    fn retrieve_local_secret(&self, config: &PinBackendConfig) -> anyhow::Result<crate::locked::Vec> {
        match self {
            Self::Age => {
                let config = config.age.as_ref().ok_or(anyhow!("age config not set"))?;
                AgePinBackend.retrieve_local_secret(&config)
            }
            Self::OSKeyring => {
                let config = config.keyring.as_ref().ok_or(anyhow!("age config not set"))?;
                KeyringPinBackend.retrieve_local_secret(&config)
            }
        }
    }

    fn store_local_secret(&self, kek: &crate::locked::Vec, config: &PinBackendConfig) -> anyhow::Result<()> {
        match self {
            Self::Age => {
                let config = config.age.as_ref().ok_or(anyhow!("age config not set"))?;
                AgePinBackend.store_local_secret(kek, &config)
            },
            Self::OSKeyring => {
                let config = config.keyring.as_ref().ok_or(anyhow!("keyring config not set"))?;
                KeyringPinBackend.store_local_secret(kek, &config)
            }
        }
    }

    fn clear_local_secret(&self) -> anyhow::Result<()> {
        match self {
            Self::Age => AgePinBackend.clear_local_secret(),
            Self::OSKeyring => KeyringPinBackend.clear_local_secret()
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PinBackendConfig {
    pub enable_pin: bool,
    #[serde(flatten)]
    pub kdf_params: Option<Argon2Params>,
    // Age
    #[serde(flatten)]
    pub age: Option<AgeConfig>,
    // OsKeyring
    #[serde(flatten)]
    pub keyring: Option<KeyringConfig>,
}


pub trait BackendConfig { }

impl PinBackendConfig {
    pub fn new() -> Self {
        Self {
            enable_pin: false,
            kdf_params: Some(Argon2Params::new()),
            age: Some(AgeConfig::new()),
            keyring: None
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct PinState {
    wrapped_keys: WrappedKey,
    wrapped_org_keys: HashMap<String, WrappedKey>,
    salt: String,
    kdf_params: Argon2Params,
    pub empty_pin: bool,
    pub backend: Backend
}

impl PinState {
    pub fn new(
        wrapped_keys: WrappedKey,
        wrapped_org_keys: HashMap<String, WrappedKey>,
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

    pub fn unpack(&self) -> anyhow::Result<(WrappedKey, HashMap<String, WrappedKey>, SaltString, Argon2Params, bool, Backend)> {
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
            self.empty_pin,
            self.backend.clone()
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

}

