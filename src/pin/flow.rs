#![cfg(feature = "pin")]
/*
Here is the logic for the high level flow of accessing the master symmetric key with the pin
*/

use std::collections::HashMap;
use anyhow::{Context};
use argon2::password_hash::SaltString;
use rand::{RngCore};
use rand::rngs::{OsRng};
use crate::{pin, dirs, error};
use crate::pin::crypto::{Argon2Params};
use crate::config::Config;
use crate::locked::{Vec, Keys, Password};
use crate::pin::backend::{PinBackend, Backend, PinState};

// TODO think about whether this needs to be an async function
// I think I do need this
pub async fn check_if_pin_available_async() -> bool {
    let state_file = dirs::pin_state_file();
    eprintln!("{:?}", state_file);
    let wrapped_ls_file = dirs::pin_wrapped_local_secret_file();
    eprintln!("{:?}", wrapped_ls_file);
    let (a, b) = tokio::try_join!(
        tokio::fs::try_exists(state_file),
        tokio::fs::try_exists(wrapped_ls_file),
    ).unwrap_or((false, false)); // TODO understand why the join could fail
    a && b
}

pub fn check_if_pin_available() -> bool {
    let state_file = dirs::pin_state_file();
    let wrapped_ls_file = dirs::pin_wrapped_local_secret_file();
    std::fs::exists(state_file).is_ok_and(|b| b) &&
    std::fs::exists(wrapped_ls_file).is_ok_and(|b| b)
}

// TODO if pin state file doesn't parse properly surface that
// TODO validate pin config
pub fn status() -> anyhow::Result<()> {
   let state_exists =
       std::fs::exists(dirs::pin_state_file()).is_ok_and(|b| b) &&
       std::fs::exists(dirs::pin_wrapped_local_secret_file()).is_ok_and(|b| b)
       ;
   std::fs::exists(dirs::pin_wrapped_local_secret_file())?;
   // let pin_state = PinState::read_from_file(dirs::pin_state_file())?;
   println!(
       "\
        Pin enabled: {} \
       ",
        state_exists
   );
   Ok(())
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

    let backend = crate::pin::backend_age::AgePinBackend; // TODO for now this is fixed
    // But I want to implement OS keyring

    let local_secret = backend.retrieve_local_secret(&config)
        .map_err(|_| error::Error::IncorrectPassword {message: "Couldn't retrieve local secret".into()})?;

    let kek = pin::crypto::derive_kek_from_pin(pin, &local_secret, &salt, &kdf_params)
        .map_err(|_| error::Error::IncorrectPassword {message: "Couldn't retrieve local secret".into()})?;

    let (keys, org_keys) = pin::crypto::unwrap_dek(&kek, wrapped_key, wrapped_org_keys)
        .map_err(|_| error::Error::IncorrectPassword {message: "PIN is not correct".into()})?;

    Ok((keys, org_keys))
}


// TODO evaluate whether it is worth it to make this async
pub fn register(keys: &Keys, org_keys: &HashMap<String, Keys>, pin: Option<&Password>, config: &Config, backend: Backend) -> anyhow::Result<()> {

    let local_secret = generate_local_secret();

    backend.store_local_secret(&local_secret, &config)?;

    let default_kdf_params = Argon2Params::new();
    let kdf_params = if let Some(pin_config) = config.pin_config.as_ref() {
        &pin_config.kdf_params.clone().unwrap_or(default_kdf_params)
    } else {
        &default_kdf_params
    };

    let salt = SaltString::generate(&mut OsRng);
    let kek = pin::crypto::derive_kek_from_pin(pin, &local_secret, &salt, &kdf_params)?;

    let (wrapped_keys, wrapped_org_keys) = pin::crypto::wrap_dek(&kek, &keys, &org_keys)?;

    let state_to_save = PinState::new(
        wrapped_keys,
        wrapped_org_keys,
        salt,
        kdf_params.clone(),
        pin.is_none(),
        backend
    )?;

    state_to_save.write_to_file()?;

    Ok(())
}

pub fn clear() -> anyhow::Result<()> {

    let backend = crate::pin::backend::PinState::read_from_file(
        dirs::pin_state_file()
    ).map(|pc| pc.backend)?;
    backend.clear_local_secret()?;
    let pin_state_file = dirs::pin_state_file();
    if std::fs::exists(pin_state_file).is_ok() {
        std::fs::remove_file(dirs::pin_state_file())?;
    }
    Ok(())
}

pub fn empty_pin() -> bool {
    PinState::read_from_file(dirs::pin_state_file())
        .map(|s| s.empty_pin)
        .unwrap_or(false)
}

// simply generate 32 bytes
fn generate_local_secret() -> Vec {
    let mut buf = Vec::new();
    buf.extend(std::iter::repeat_n(0, 32));
    rand::thread_rng().fill_bytes(buf.data_mut());
    buf
}

fn get_backend() -> anyhow::Result<Backend> {
    let pin_state = PinState::read_from_file(dirs::pin_state_file())?;

    Ok(pin_state.backend)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup() {

    }
}