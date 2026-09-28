use crate::locked::Vec;
use crate::pin::crypto::LOCAL_SECRET_LEN;
use anyhow::bail;
use keyring::credential::CredentialPersistence;
use zeroize::Zeroizing;

const SERVICE: &str = "rbw";

fn entry() -> anyhow::Result<keyring::Entry> {
    Ok(keyring::Entry::new(SERVICE, &crate::dirs::profile())?)
}

/// keyring silently falls back to an in-memory mock store on platforms
/// without a supported keyring, so refuse to use it unless secrets persist.
pub fn check_available() -> anyhow::Result<()> {
    let persistence =
        keyring::default::default_credential_builder().persistence();
    if !matches!(persistence, CredentialPersistence::UntilDelete) {
        bail!("no persistent OS keyring is available on this platform");
    }
    Ok(())
}

pub fn store(local_secret: &Vec) -> anyhow::Result<()> {
    check_available()?;
    entry()?.set_secret(local_secret.data())?;
    Ok(())
}

pub fn retrieve() -> anyhow::Result<Vec> {
    let secret = Zeroizing::new(entry()?.get_secret()?);
    if secret.len() != LOCAL_SECRET_LEN {
        bail!("local secret in the OS keyring has the wrong length");
    }
    let mut local_secret = Vec::new();
    local_secret.extend(secret.iter().copied());
    Ok(local_secret)
}

pub fn clear() -> anyhow::Result<()> {
    match entry()?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.into()),
    }
}
