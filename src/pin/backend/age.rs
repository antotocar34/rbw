use crate::locked::Vec;
use crate::pin::backend::{remove_file_if_exists, write_private_file};
use crate::pin::crypto::LOCAL_SECRET_LEN;
use age::plugin;
use anyhow::{anyhow, bail, Context as _};
use std::io::Read as _;
use std::path::Path;

pub const SUPPORTED_AGE_PLUGINS: [&str; 3] = [
    "yubikey", // https://github.com/str4d/age-plugin-yubikey
    "tpm",     // https://github.com/Foxboron/age-plugin-tpm
    "se",      // https://github.com/remko/age-plugin-se
];

pub fn validate(identity_file: &Path) -> anyhow::Result<()> {
    if !identity_file.is_file() {
        bail!("age identity file {} not found", identity_file.display());
    }
    identity(identity_file, age::NoCallbacks).map(|_| ())
}

pub fn store<C: age::Callbacks>(
    local_secret: &Vec,
    identity_file: &Path,
    secret_file: &Path,
    callbacks: C,
) -> anyhow::Result<()> {
    let (_, recipient) = identity(identity_file, callbacks)?;
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(recipient.as_ref()))?;

    let mut encrypted = std::vec::Vec::new();
    let mut writer = encryptor.wrap_output(&mut encrypted)?;
    std::io::Write::write_all(&mut writer, local_secret.data())?;
    writer.finish()?;

    write_private_file(secret_file, &encrypted)
}

pub fn retrieve<C: age::Callbacks>(
    identity_file: &Path,
    secret_file: &Path,
    callbacks: C,
) -> anyhow::Result<Vec> {
    let (identity, _) = identity(identity_file, callbacks)?;
    let file = std::fs::File::open(secret_file)
        .context("could not open age-wrapped local secret")?;
    let decryptor = age::Decryptor::new(std::io::BufReader::new(file))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(identity.as_ref()))
        .context("failed to decrypt age-wrapped local secret")?;

    let mut local_secret = Vec::new();
    local_secret.extend(std::iter::repeat_n(0, LOCAL_SECRET_LEN));
    reader.read_exact(local_secret.data_mut())?;
    if reader.read(&mut [0])? != 0 {
        bail!("age-wrapped local secret has the wrong length");
    }
    Ok(local_secret)
}

pub fn clear(secret_file: &Path) -> anyhow::Result<()> {
    remove_file_if_exists(secret_file)
}

type IdentityAndRecipient = (Box<dyn age::Identity>, Box<dyn age::Recipient>);

fn identity<C: age::Callbacks>(
    identity_file: &Path,
    callbacks: C,
) -> anyhow::Result<IdentityAndRecipient> {
    let contents =
        std::fs::read_to_string(identity_file).with_context(|| {
            format!("could not read age identity {}", identity_file.display())
        })?;
    let line = contents
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .ok_or_else(|| anyhow!("age identity file is empty"))?;

    if let Ok(identity) = line.parse::<plugin::Identity>() {
        if !SUPPORTED_AGE_PLUGINS.contains(&identity.plugin()) {
            bail!("age plugin '{}' is not supported", identity.plugin());
        }
        let id_plugin = plugin::IdentityPluginV1::new(
            identity.plugin(),
            std::slice::from_ref(&identity),
            callbacks.clone(),
        )
        .context("failed to initialize age plugin identity")?;
        let rec_plugin = plugin::RecipientPluginV1::new(
            identity.plugin(),
            &[],
            std::slice::from_ref(&identity),
            callbacks,
        )
        .context("failed to initialize age plugin recipient")?;
        return Ok((Box::new(id_plugin), Box::new(rec_plugin)));
    }

    // plain x25519 identities aren't device-bound, so they're only accepted
    // in tests
    #[cfg(test)]
    if let Ok(identity) = line.parse::<age::x25519::Identity>() {
        let recipient = identity.to_public();
        return Ok((Box::new(identity), Box::new(recipient)));
    }

    bail!("{} is not an age plugin identity", identity_file.display())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const TEST_IDENTITY: &str = "AGE-SECRET-KEY-1J6CR00H6EZHNT6R7PP0RM2ADCV2F49Z32XFJLP89VGK6Z4NJRHYQV82S8U";

    #[test]
    fn pin_age_store_retrieve() {
        let dir = tempfile::tempdir().unwrap();
        let identity_file = dir.path().join("identity.txt");
        std::fs::write(
            &identity_file,
            format!("# comment\n{TEST_IDENTITY}\n"),
        )
        .unwrap();
        let secret_file = dir.path().join("secret.age");

        let mut secret = Vec::new();
        secret.extend(std::iter::repeat_n(b'0', LOCAL_SECRET_LEN));

        validate(&identity_file).unwrap();
        store(&secret, &identity_file, &secret_file, age::NoCallbacks)
            .unwrap();
        let retrieved =
            retrieve(&identity_file, &secret_file, age::NoCallbacks).unwrap();
        assert_eq!(retrieved.data(), secret.data());

        clear(&secret_file).unwrap();
        assert!(!secret_file.exists());
        // clearing twice is fine
        clear(&secret_file).unwrap();
    }

    #[test]
    fn pin_age_validate_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(validate(&dir.path().join("missing")).is_err());
    }
}
