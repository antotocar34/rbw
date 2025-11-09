use crate::prelude::*;
use std::fs;
use std::io::{BufReader, Read, Write};

// #![cfg(feature = "pin")]
use std::path::PathBuf;
use std::fs::File;
use std::os::unix::fs::OpenOptionsExt;
use serde::{Deserialize, Serialize};
use age::{plugin, Decryptor};
use crate::locked::Vec;
use crate::error::{Error, Result};
use crate::config::Config;

pub const SUPPORTED_PLUGINS: [&'static str; 3] = [
    "yubikey", // https://github.com/str4d/age-plugin-yubikey
    "tpm", // https://github.com/Foxboron/age-plugin-tpm
    "se" // https://github.com/remko/age-plugin-se
];

#[derive(Debug, Serialize, Deserialize)]
pub struct PinBackendConfig {
    identity_file_path: PathBuf,
    encrypted_local_secret_file: Option<PathBuf>
}

impl PinBackendConfig {
    fn identity(&self) -> anyhow::Result<plugin::Identity> {
        let age_identity = fs::read_to_string(&self.identity_file_path)?;

        // Remove hashes
        // TODO improve parsing code
        let cleaned_string: String = age_identity
            .lines()
            .filter(|s| !s.starts_with('#'))
            .map(|s| s.trim())
            .collect();

        let identity =
            cleaned_string.as_str().parse::<plugin::Identity>().map_err(|e| anyhow::anyhow!(e))?;


        if SUPPORTED_PLUGINS.iter().all(|&x| x != identity.plugin()) {
            return Err(anyhow::anyhow!("Plugin is not supported"))
        };

        Ok(identity)
    }
}

trait PinBackend {
    fn retrieve_local_secret(&self, config: &Config) -> anyhow::Result<Vec>;
    fn store_local_secret(&self, kek: Vec, config: &Config) -> Result<()>;
}

struct AgePinBackend; // TODO figure out what to do here

impl PinBackend for AgePinBackend {
    fn retrieve_local_secret(&self, config: &Config) -> anyhow::Result<Vec> {
        let pin_config = config.pin_config.as_ref().ok_or(anyhow::anyhow!("Pin config not set"))?;
        let age_file_path = {
            let path = pin_config.encrypted_local_secret_file.as_ref();
            path.ok_or(anyhow::anyhow!(""))?
        };

        let identity = pin_config.identity()?;

        let identity_plugin = plugin::IdentityPluginV1::new(
            &identity.plugin(),
            &[identity.clone()],
            age::NoCallbacks
        )?;

        let reader = BufReader::new(
            File::open(age_file_path)?
        );
        let decryptor = Decryptor::new(reader)?;

        let mut decrypted_reader = decryptor.decrypt(std::iter::once(&identity_plugin as &dyn age::Identity))?;

        let mut kek = Vec::new();
        kek.extend(std::iter::repeat_n(0, 32));

        decrypted_reader.read_exact(kek.data_mut())?;

        Ok(kek)
    }

    fn store_local_secret(&self, kek: Vec, config: &Config) -> Result<()> {

        let identity = match config.pin_config.as_ref() {
            Some(pin_config) => pin_config.identity(),
            None => return Err(Error::NotImplemented),
        }.map_err(|_| Error::NotImplemented)?;

        let plugin_recipient = plugin::RecipientPluginV1::new(
            &identity.plugin(),
            &[],
            &[identity.clone()],
            age::NoCallbacks, // works as long as the plugin never needs interactive input
        ).map_err(|_| Error::NotImplemented)?;

        let recipient = &plugin_recipient as &dyn age::Recipient;

        let mut out = {
            let pin_config = config.pin_config.as_ref().ok_or(Error::NotImplemented)?;
            let encrypted_age_path = pin_config
                .encrypted_local_secret_file
                .as_ref()
                .ok_or(Error::NotImplemented)?;

            let file = fs::OpenOptions::new()
                .write(true)
                .mode(0o600)
                .create(true)
                .open(encrypted_age_path)
                .map_err(|_| Error::NotImplemented)?;
            file
        };

        let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient))
            .map_err(|_| Error::NotImplemented)?;
        let mut writer = encryptor.wrap_output(&mut out)
            .map_err(|_| Error::NotImplemented)?;

        writer.write_all(kek.data())
            .map_err(|_| Error::NotImplemented)?;
        writer.finish()
            .map_err(|_| Error::NotImplemented)?;

        out.sync_all().ok();

        Ok(())
    }
}


mod tests {
    use super::*;

    use crate::config::Config;

    const DUMMY_IDENTITY: &str = "AGE-PLUGIN-SE-1QJPQZSP3SGQNCVYP75XQYUNTXXQ7UVQTPSPKY6TYQSZ86D7RUGCYSRQRWP6KYPZPQ338C2YRPH6W355K58YUN5TQLEG2K2RRTKG4TCN9HRJVEGFWGC5C55K8S3ZN6NH4TEK7KC9JDZDGRE83DVSLDMJR6KYD4QKE4NRWS868XQYQCQMJDDHSYQGQXQRSCQNTWSPQZPPS9CXQYAMTQS5036M7ACXRYG640MLP7KL0TDE240HK3F429FHEYMM6GXGCJNNFMNWZ0Q5EZ26AXD3NQPCVQF3XXQSPPYCQWRQZDDMQYQGZXQTSCQMTD9JQGY9HGFW0WVD4FN26Y35VCX0N9K0CXQNSCQMJDDKSGG9UQ9UDHE398787C2YY5WW8E6T8W5H3NHKTVM8TSHLAC0AA0J3CKVCYYRQZV4JRZ0PS8GXQXCTRDSCNXVQGPSPK7CMTQYQSZVQFPSZX7ER9DSQSZQFSPYXQGMMNVAHQZQGPXQRSCQN0VYQSZQFSPQXQXMMTVSQSZQGV24NPH";
    const DUMMY_KEY: &[u8; 32] = &[b'0'; 32];

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

        let pin_config = PinBackendConfig {
            identity_file_path: identity_file.path().into(),
            encrypted_local_secret_file: None
        };

        match pin_config.identity() {
            Ok(_) => (),
            Err(_) => assert!(false)
        }
    }

    #[test]
    fn pin_age_plugin_encrypt_decrypt() {
        let identity_file = create_temp_file_of_contents(DUMMY_IDENTITY.as_bytes());
        let encrypted_local_secret_file = create_temp_file_of_contents(&[]);
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
                PinBackendConfig {
                    identity_file_path: identity_file.path().into(),
                    encrypted_local_secret_file: Some(encrypted_local_secret_file.path().into())
                }
            )
        };

        let dummy_kek = create_vec(&[b'0'; 32]);

        let backend = AgePinBackend;

        backend.store_local_secret(dummy_kek, &config).unwrap();

        let decrypted_kek = backend.retrieve_local_secret(&config).unwrap();

        assert_eq!(decrypted_kek.data(), [b'0';32].as_ref())
    }
}