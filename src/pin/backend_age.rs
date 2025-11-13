#![cfg(feature = "pin")]
use std::fs;
use std::io::{BufReader, Read, Write};

use std::fs::File;
use std::os::unix::fs::OpenOptionsExt;
use serde::{Deserialize, Serialize};
use age::{plugin, Decryptor};
use anyhow::{anyhow, Context};
use crate::locked::Vec;
use crate::config::Config;
use crate::dirs;
use crate::pin::backend::PinBackend;

pub const SUPPORTED_AGE_PLUGINS: [&str; 3] = [
    "yubikey", // https://github.com/str4d/age-plugin-yubikey
    "tpm",     // https://github.com/Foxboron/age-plugin-tpm
    "se"       // https://github.com/remko/age-plugin-se
];



#[derive(Serialize, Deserialize)]
pub struct AgePinBackend; // TODO figure out what to do here


impl PinBackend for AgePinBackend {
    fn retrieve_local_secret(&self, config: &Config) -> anyhow::Result<Vec> {
        let age_file_path = dirs::pin_wrapped_local_secret_file();

        let pin_config = config.pin_config
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Pin config not set"))?;
        let identity = age_identity(pin_config)?;

        let identity_plugin = plugin::IdentityPluginV1::new(
            identity.plugin(),
            std::slice::from_ref(&identity),
            age::NoCallbacks
        ).context(format!("Could not construct age plugin identity. Is age-plugin-{} in your $PATH?", &identity.plugin()))?;

        let reader = BufReader::new(
            File::open(age_file_path)?
        );
        let decryptor = Decryptor::new(reader)?;

        let mut decrypted_reader =
            decryptor.decrypt(std::iter::once(&identity_plugin as &dyn age::Identity))
                .context("Failed to decrypt age wrapped local secret")?;

        let mut kek = Vec::new();
        kek.extend(std::iter::repeat_n(0, crate::pin::crypto::KEK_LEN));

        decrypted_reader.read_exact(kek.data_mut())?;

        Ok(kek)
    }

    fn store_local_secret(&self, local_secret: &Vec, config: &Config) -> anyhow::Result<()> {

        let identity = match config.pin_config.as_ref() {
            Some(pin_config) => age_identity(pin_config),
            None => anyhow::bail!("Age identity not found.")
        }?;

        let plugin_recipient = plugin::RecipientPluginV1::new(
            identity.plugin(),
            &[],
            std::slice::from_ref(&identity),
            age::NoCallbacks,
        )?;

        let recipient = &plugin_recipient as &dyn age::Recipient;

        let mut stored_secret = {
            let encrypted_age_path = dirs::pin_wrapped_local_secret_file();

            let file = fs::OpenOptions::new()
                .write(true)
                .mode(0o600)
                .create(true)
                .truncate(true) // TODO if encrypting fails then this might not be a good idea :/
                .open(encrypted_age_path)?;
            file
        };

        let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient))?;
        let mut writer = encryptor.wrap_output(&mut stored_secret)?;

        writer.write_all(local_secret.data())?;
        writer.finish()?;
        stored_secret.sync_all().ok();

        Ok(())
    }

    fn clear_local_secret(&self) -> anyhow::Result<()> {
        fs::remove_file(dirs::pin_wrapped_local_secret_file())
            .context("Failed to remove the age wrapped local secret.")?;
        Ok(())
    }
}

fn age_identity(pin_config: &crate::pin::backend::PinBackendConfig) -> anyhow::Result<plugin::Identity> {
    let age_identity = fs::read_to_string(
        pin_config.age_identity_file_path
            .as_ref()
            .ok_or_else(|| anyhow!("Could not read the age identity file"))?
    )?;

    // Remove '#' comments
    let cleaned_string: String = age_identity
        .lines()
        .filter(|s| !s.trim_start().starts_with('#'))
        .map(str::trim)
        .collect::<std::vec::Vec<_>>()
        .join("\n");

    let identity = cleaned_string
        .as_str()
        .parse::<plugin::Identity>()
        .map_err(|e| anyhow::anyhow!("Could not the parse age-plugin-* identity: {}", e))?;


    if SUPPORTED_AGE_PLUGINS.iter().all(|&x| x != identity.plugin()) {
        anyhow::bail!("Plugin is not supported")
    }

    Ok(identity)
}



#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::Config;

    const DUMMY_IDENTITY: &str = "AGE-PLUGIN-SE-1QJPQZSP3SGQNCVYP75XQYUNTXXQ7UVQTPSPKY6TYQSZ86D7RUGCYSRQRWP6KYPZPQ338C2YRPH6W355K58YUN5TQLEG2K2RRTKG4TCN9HRJVEGFWGC5C55K8S3ZN6NH4TEK7KC9JDZDGRE83DVSLDMJR6KYD4QKE4NRWS868XQYQCQMJDDHSYQGQXQRSCQNTWSPQZPPS9CXQYAMTQS5036M7ACXRYG640MLP7KL0TDE240HK3F429FHEYMM6GXGCJNNFMNWZ0Q5EZ26AXD3NQPCVQF3XXQSPPYCQWRQZDDMQYQGZXQTSCQMTD9JQGY9HGFW0WVD4FN26Y35VCX0N9K0CXQNSCQMJDDKSGG9UQ9UDHE398787C2YY5WW8E6T8W5H3NHKTVM8TSHLAC0AA0J3CKVCYYRQZV4JRZ0PS8GXQXCTRDSCNXVQGPSPK7CMTQYQSZVQFPSZX7ER9DSQSZQFSPYXQGMMNVAHQZQGPXQRSCQN0VYQSZQFSPQXQXMMTVSQSZQGV24NPH";

    fn create_temp_file_of_contents(contents: &[u8]) -> tempfile::NamedTempFile {
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
        let identity_file = create_temp_file_of_contents(DUMMY_IDENTITY.as_bytes());

        let pin_config = crate::pin::backend::PinBackendConfig {
            enable_pin: true,
            local_secret_keyring_entry_name: None,
            age_identity_file_path: Some(identity_file.path().into()),
            kdf_params: Some(crate::pin::crypto::Argon2Params::new())
        };

        match age_identity(&pin_config) {
            Ok(_) => (),
            Err(_) => assert!(false)
        }
    }

    #[test]
    fn pin_age_plugin_store_retrieve() {
        let identity_file = create_temp_file_of_contents(DUMMY_IDENTITY.as_bytes());
        let config = Config {
            email: None,
            sso_id: None,
            base_url: None,
            identity_url: None,
            ui_url: None,
            notifications_url: None,
            lock_timeout: 60*60*24,
            sync_interval: 1000,
            pinentry: "".to_string(),
            client_cert_path: None,
            device_id: None,
            pin_config: Some(
                crate::pin::backend::PinBackendConfig {
                    enable_pin: true,
                    local_secret_keyring_entry_name: None,
                    age_identity_file_path: Some(identity_file.path().into()),
                    kdf_params: Some(crate::pin::crypto::Argon2Params::new())
                }
            )
        };

        let dummy_kek = create_vec(&[b'0'; 32]);

        let backend = AgePinBackend;

        backend.store_local_secret(&dummy_kek, &config).unwrap();

        let decrypted_kek = backend.retrieve_local_secret(&config).unwrap();

        assert_eq!(decrypted_kek.data(), [b'0';32].as_ref())
    }
}