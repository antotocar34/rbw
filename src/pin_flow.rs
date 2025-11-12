#![cfg(feature = "pin")]
/*
Here is the logic for the high level flow of accessing the master symmetric key with the pin
*/

use std::collections::HashMap;
use argon2::password_hash::SaltString;
use rand::{RngCore};
use rand::rngs::{OsRng};
use crate::{dirs, error, pin_crypto};
use crate::pin_crypto::{PinState, Argon2Params};
use crate::pin_age_backend::PinBackend;
use crate::config::Config;
use crate::locked::{Vec, Keys, Password};


pub fn check_if_pin_available() -> bool {
    std::fs::exists(dirs::pin_state_file()).is_ok() &&
    std::fs::exists(dirs::pin_wrapped_local_secret_file()).is_ok()
}

// TODO redo the Incorrect Password Error Messages to something much more sensible
// Meaning for return something else for an unrecoverable error
pub fn unlock_with_pin(pin: Option<&Password>, config: Config) -> error::Result<(Keys, HashMap<String, Keys>)> {

    let state = PinState::read_from_file(dirs::pin_state_file())
        .map_err(|_| error::Error::IncorrectPassword {message: "Couldn't read pin state".into()})?;

    // TODO should this function be outside?
    let (
        wrapped_key,
        wrapped_org_keys,
        salt,
        kdf_params,
        _
    ) = state.unpack()
        .map_err(|_| error::Error::IncorrectPassword {message: "Couldn't deserialize pin state".into()})?;

    let backend = crate::pin_age_backend::AgePinBackend; // TODO for now this is fixed
                                                         // But I want to implement OS keyring

    let local_secret = backend.retrieve_local_secret(&config)
        .map_err(|_| error::Error::IncorrectPassword {message: "Couldn't retrieve local secret".into()})?;

    let kek = pin_crypto::derive_kek_from_pin(pin, &local_secret, &salt, &kdf_params)
        .map_err(|_| error::Error::IncorrectPassword {message: "Couldn't retrieve local secret".into()})?;

    let (keys, org_keys) = pin_crypto::unwrap_dek(&kek, wrapped_key, wrapped_org_keys)
        .map_err(|_| error::Error::IncorrectPassword {message: "PIN is not correct".into()})?;

    Ok((keys, org_keys))
}

pub fn register_pin(keys: &Keys, org_keys: &HashMap<String, Keys>, pin: Option<&Password>, config: &Config, backend: &crate::pin_age_backend::AgePinBackend) -> anyhow::Result<()> {

    let salt = SaltString::generate(&mut OsRng);
    let local_secret = generate_local_secret();

    backend.store_local_secret(&local_secret, &config)?;

    let kdf_params = if let Some(pin_config) = config.pin_config.as_ref() {
        &pin_config.kdf_params
    } else {
        &Argon2Params::new()
    };

    let kek = pin_crypto::derive_kek_from_pin(pin, &local_secret, &salt, &kdf_params)?;

    let (wrapped_keys, wrapped_org_keys) = pin_crypto::wrap_dek(&kek, &keys, &org_keys)?;

    let state_to_save = PinState::new(wrapped_keys, wrapped_org_keys, salt, kdf_params.clone(), pin.is_none())?; // TODO not a fan of the clone here

    state_to_save.write_to_file()?;

    Ok(())
}

// Simple clear state file and
pub fn clear_pin(backend: &crate::pin_age_backend::AgePinBackend) -> anyhow::Result<()> {
    backend.clear_local_secret()?;
    std::fs::remove_file(dirs::pin_state_file())?;
    Ok(())
}

pub fn empty_pin() -> bool {
    // match PinState::read_from_file(crate::dirs::pin_state_file());
    false
}

// simply generate 32 bytes
fn generate_local_secret() -> Vec {
    let mut buf = Vec::new();
    buf.extend(std::iter::repeat_n(0, 32));
    rand::thread_rng().fill_bytes(buf.data_mut());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup() {

    }
}