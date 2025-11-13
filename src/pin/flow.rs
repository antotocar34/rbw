#![cfg(feature = "pin")]
/*
Here is the logic for the high level flow of accessing the master symmetric key with the pin
*/

use std::collections::HashMap;
use anyhow::{Context};
use argon2::password_hash::SaltString;
use rand::{RngCore};
use rand::rngs::{OsRng};
use rustix::path::Arg;
use crate::{pin, dirs, error};
use crate::pin::crypto::{wrap_dek, Argon2Params};
use crate::config::Config;
use crate::locked::{Vec, Keys, Password};
use crate::pin::backend::{PinBackend, Backend, PinState};

// TODO think about whether this needs to be an async function
// I think I do need this
pub async fn check_if_pin_available_async() -> bool {
    let state_file = dirs::pin_state_file();
    let wrapped_ls_file = dirs::pin_wrapped_local_secret_file();

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


   // TODO this is age only
   let state_exists =
       std::fs::exists(dirs::pin_state_file()).is_ok_and(|b| b) &&
       std::fs::exists(dirs::pin_wrapped_local_secret_file()).is_ok_and(|b| b)
       ;

   let enabled_msg = format!("Pin enabled: {}", state_exists);

   let mut backend_msg = "".to_string();
   if let Ok(pin_state) = load_pin_state() {
       let backend = pin_state.backend;
       let backend_name = match backend {
           Backend::Age => "age",
           Backend::OSKeyring => "keyring"
       };
       backend_msg.push_str(format!("Backend: {}", backend_name).as_str());
   }
   let parts = [ enabled_msg, backend_msg];
   let msg = parts.join("\n");
   println!(
       "{msg}"
   );
   Ok(())
}

// Meaning for return something else for an unrecoverable error
pub fn unlock_with_pin(pin: Option<&Password>, pin_state: PinState, config: Config) -> error::Result<(Keys, HashMap<String, Keys>)> {

    let (
        wrapped_key,
        wrapped_org_keys,
        salt,
        kdf_params,
        _,
        backend,
    ) = pin_state.unpack()
        .map_err(|_| error::Error::PinError {message: "Couldn't deserialize pin state".into()})?;

    let local_secret = backend.retrieve_local_secret(&config)
        .map_err(|_| error::Error::PinError {message: "Couldn't retrieve local secret".into()})?;

    let kek = pin::crypto::derive_kek_from_pin(pin, &local_secret, &salt, &kdf_params)?;

    let (keys, org_keys) = pin::crypto::unwrap_dek(&kek, &wrapped_key, &wrapped_org_keys)
        .map_err(|_| error::Error::IncorrectPassword {message: "Incorrect PIN".into()})?;

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
    let kek = pin::crypto::derive_kek_from_pin(pin, &local_secret, &salt, kdf_params)?;

    let (wrapped_keys, wrapped_org_keys) = pin::crypto::wrap_dek(&kek, keys, org_keys)?;

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

    // Try to clear the secret if we can read the state.
    if let Ok(state) = PinState::read_from_file(dirs::pin_state_file())
        .context("reading pin state file")
    {
        state.backend
            .clear_local_secret()
            .context("clearing local secret")?;
    };

    match std::fs::remove_file(&dirs::pin_state_file()) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context("removing pin state file"),
    }

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

fn load_pin_state() -> anyhow::Result<PinState> {
    let pin_state = PinState::read_from_file(dirs::pin_state_file())?;

    Ok(pin_state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup() {

    }
}