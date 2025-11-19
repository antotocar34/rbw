use std::fs;
use std::io::{BufReader, Read, Write};

use crate::dirs;
use crate::locked::Vec;
use crate::pin;
use crate::pin::backend::{BackendConfig, PinBackend};
use age::{plugin, Decryptor};
use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

pub const SUPPORTED_AGE_PLUGINS: [&str; 3] = [
    "yubikey", // https://github.com/str4d/age-plugin-yubikey
    "tpm",     // https://github.com/Foxboron/age-plugin-tpm
    "se",      // https://github.com/remko/age-plugin-se
];

#[derive(Serialize, Deserialize)]
pub struct AgePinBackend;

#[derive(Serialize, Deserialize, Debug)]
pub struct AgeConfig {
    #[serde(rename = "age_identity_file_path")]
    pub identity_file_path: PathBuf,
}

impl Default for AgeConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl AgeConfig {
    pub fn new() -> Self {
        Self {
            identity_file_path: "".into(),
        }
    }
    fn _validate(&self) -> anyhow::Result<()> {
        match fs::exists::<&PathBuf>(&self.identity_file_path) {
            Ok(_) => Ok(()),
            Err(_) => Err(anyhow!("Age identity file not found")),
        }

        // TODO check if the file is parseable and the plugin is supported
        // this is enough for now
    }
}

impl BackendConfig for AgeConfig {}

impl PinBackend for AgePinBackend {
    type Config = AgeConfig;
    fn retrieve_local_secret(
        &self,
        config: &AgeConfig,
    ) -> anyhow::Result<Vec> {
        let age_file_path = dirs::pin_age_wrapped_local_secret_file();

        let identity = age_identity(config).context("could not parse age identity")?;

        let identity_plugin = plugin::IdentityPluginV1::new(
            identity.plugin(),
            std::slice::from_ref(&identity),
            age::NoCallbacks
        ).context(format!("could not construct age plugin identity. Is age-plugin-{} in your $PATH?", &identity.plugin()))?;

        let reader = BufReader::new(File::open(age_file_path)?);
        let decryptor = Decryptor::new(reader)?;

        let identities: [&dyn age::Identity; 1] = [&identity_plugin];
        let mut decrypted_reader = decryptor
            .decrypt(identities.into_iter())
            .context("Failed to decrypt age wrapped local secret")?;

        let mut kek = Vec::new();
        kek.extend(std::iter::repeat_n(0, pin::crypto::KEK_LEN));

        decrypted_reader.read_exact(kek.data_mut())?;

        Ok(kek)
    }

    fn store_local_secret(
        &self,
        local_secret: &Vec,
        config: &AgeConfig,
    ) -> anyhow::Result<()> {
        let identity = age_identity(config)?;

        let plugin_recipient = plugin::RecipientPluginV1::new(
            identity.plugin(),
            &[],
            std::slice::from_ref(&identity),
            age::NoCallbacks,
        )?;

        let mut stored_secret = {
            let encrypted_age_path =
                dirs::pin_age_wrapped_local_secret_file();

            let file = fs::OpenOptions::new()
                .write(true)
                .mode(0o600)
                .create(true)
                .truncate(true) // TODO if encryption fails then this might not be a good idea :/
                .open(encrypted_age_path)?;
            file
        };

        let recipients: [&dyn age::Recipient; 1] = [&plugin_recipient; 1];
        let encryptor =
            age::Encryptor::with_recipients(recipients.into_iter())?;
        let mut writer = encryptor.wrap_output(&mut stored_secret)?;

        writer.write_all(local_secret.data())?;
        writer.finish()?;
        stored_secret.sync_all().ok();

        Ok(())
    }

    fn clear_local_secret(&self) -> anyhow::Result<()> {
        fs::remove_file(dirs::pin_age_wrapped_local_secret_file())
            .context("Failed to remove the age wrapped local secret.")?;
        Ok(())
    }
}

fn age_identity(
    config: &pin::backend::age::AgeConfig,
) -> anyhow::Result<plugin::Identity> {
    let age_identity = fs::read_to_string(&config.identity_file_path)?;

    // Remove '#' comments and empty newlines
    let cleaned_string: String = age_identity
        .lines()
        .filter(|s| !s.trim_start().starts_with('#'))
        .filter(|s| !s.trim().eq(""))
        .map(str::trim)
        .collect::<std::vec::Vec<_>>()
        .join("\n");

    let identity = cleaned_string
        .as_str()
        .parse::<plugin::Identity>()
        .map_err(|e| {
            anyhow::anyhow!(
                "could not the parse age-plugin-* identity: {}",
                e
            )
        })?;

    if SUPPORTED_AGE_PLUGINS
        .iter()
        .all(|&x| x != identity.plugin())
    {
        anyhow::bail!("plugin is not supported")
    }

    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::Config;

    const DUMMY_IDENTITY: &str = "AGE-PLUGIN-SE-1QJPQZSP3SGQNCVYP75XQYUNTXXQ7UVQTPSPKY6TYQSZ86D7RUGCYSRQRWP6KYPZPQ338C2YRPH6W355K58YUN5TQLEG2K2RRTKG4TCN9HRJVEGFWGC5C55K8S3ZN6NH4TEK7KC9JDZDGRE83DVSLDMJR6KYD4QKE4NRWS868XQYQCQMJDDHSYQGQXQRSCQNTWSPQZPPS9CXQYAMTQS5036M7ACXRYG640MLP7KL0TDE240HK3F429FHEYMM6GXGCJNNFMNWZ0Q5EZ26AXD3NQPCVQF3XXQSPPYCQWRQZDDMQYQGZXQTSCQMTD9JQGY9HGFW0WVD4FN26Y35VCX0N9K0CXQNSCQMJDDKSGG9UQ9UDHE398787C2YY5WW8E6T8W5H3NHKTVM8TSHLAC0AA0J3CKVCYYRQZV4JRZ0PS8GXQXCTRDSCNXVQGPSPK7CMTQYQSZVQFPSZX7ER9DSQSZQFSPYXQGMMNVAHQZQGPXQRSCQN0VYQSZQFSPQXQXMMTVSQSZQGV24NPH";

    fn create_temp_file_of_contents(
        contents: &[u8],
    ) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(contents).unwrap();
        file
    }

    fn create_vec(bytes: &[u8]) -> crate::locked::Vec {
        let mut vec = crate::locked::Vec::new();
        vec.extend(bytes.iter().copied());
        vec
    }

    #[test]
    fn pin_age_parse_identity() {
        let age_identity_str = DUMMY_IDENTITY;
        let identity: plugin::Identity = age_identity_str.parse().unwrap();

        assert_eq!(identity.plugin(), "se")
    }

    #[test]
    fn pin_age_parse_identity_file() {
        let identity_file =
            create_temp_file_of_contents(DUMMY_IDENTITY.as_bytes());

        let pin_config = pin::backend::PinBackendConfig {
            enable_pin: true,
            keyring: None,
            age: Some(AgeConfig {
                identity_file_path: identity_file.path().into(),
            }),
            kdf_params: Some(pin::crypto::Argon2Params::new()),
        };

        match age_identity(&pin_config.age.unwrap()) {
            Ok(_) => (),
            Err(_) => assert!(false),
        }
    }

    #[test]
    fn pin_age_plugin_store_retrieve() {
        let identity_file =
            create_temp_file_of_contents(DUMMY_IDENTITY.as_bytes());
        let config = Config {
            email: None,
            sso_id: None,
            base_url: None,
            identity_url: None,
            ui_url: None,
            notifications_url: None,
            lock_timeout: 60 * 60 * 24,
            sync_interval: 1000,
            pinentry: "".to_string(),
            client_cert_path: None,
            device_id: None,
            pin_config: Some(pin::backend::PinBackendConfig {
                enable_pin: true,
                keyring: None,
                age: Some(AgeConfig {
                    identity_file_path: identity_file.path().into(),
                }),
                kdf_params: Some(pin::crypto::Argon2Params::new()),
            }),
        };

        let dummy_kek = create_vec(&[b'0'; 32]);

        let backend = AgePinBackend;

        let age_config = config.pin_config.unwrap().age.unwrap();

        backend.store_local_secret(&dummy_kek, &age_config).unwrap();

        let decrypted_kek =
            backend.retrieve_local_secret(&age_config).unwrap();

        assert_eq!(decrypted_kek.data(), [b'0'; 32].as_ref())
    }
}
