use crate::locked::{Keys, Password};
use crate::pin::backend::{
    remove_file_if_exists, Backend, Paths, PinBackendConfig, PinState,
};
use crate::pin::crypto;
use anyhow::{bail, Context as _};

pub fn register<C: age::Callbacks>(
    keys: &Keys,
    pin: Option<&Password>,
    config: &PinBackendConfig,
    backend: Backend,
    paths: &Paths,
    callbacks: C,
) -> anyhow::Result<()> {
    if !config.enable_pin {
        bail!(
            "PIN unlock is disabled (run `rbw config set enable_pin true`)"
        );
    }
    backend.check_available(config)?;

    let local_secret = crypto::generate_local_secret();
    let salt = crypto::generate_salt();
    let kek =
        crypto::derive_kek(pin, &local_secret, &salt, &config.kdf_params)?;
    let wrapped_key = crypto::wrap_key(&kek, keys, &crate::dirs::profile())?;
    let state = PinState::new(
        wrapped_key,
        &salt,
        config.kdf_params.clone(),
        pin.is_none(),
        backend,
    );

    // drop any existing PIN first, so that if a later step fails the user is
    // left with no PIN rather than a state file and a local secret that don't
    // match
    clear(paths)?;
    backend.store_local_secret(&local_secret, config, paths, callbacks)?;
    if let Err(e) = state.write_to_file(&paths.state_file) {
        let _ = backend.clear_local_secret(paths);
        return Err(e);
    }
    Ok(())
}

/// Recover the user key. The caller must still check it against the local
/// database (see `rbw::actions::unlock_with_key`).
pub fn unlock<C: age::Callbacks>(
    pin: Option<&Password>,
    state: &PinState,
    config: &PinBackendConfig,
    paths: &Paths,
    callbacks: C,
) -> anyhow::Result<Keys> {
    let local_secret = state
        .backend()
        .retrieve_local_secret(config, paths, callbacks)
        .context("couldn't retrieve the local secret")?;
    let kek = crypto::derive_kek(
        pin,
        &local_secret,
        &state.salt()?,
        state.kdf_params(),
    )?;
    Ok(crypto::unwrap_key(
        &kek,
        state.wrapped_key(),
        &crate::dirs::profile(),
    )?)
}

pub fn is_registered(paths: &Paths) -> bool {
    paths.state_file.exists()
}

pub fn load_state(paths: &Paths) -> anyhow::Result<PinState> {
    PinState::read_from_file(&paths.state_file)
}

/// Remove the PIN. Succeeds if there is no PIN, or if parts of it are
/// already gone.
pub fn clear(paths: &Paths) -> anyhow::Result<()> {
    let state = load_state(paths).ok();

    // remove the state file first, so PIN unlock is disabled even if cleaning
    // up the local secret fails
    remove_file_if_exists(&paths.state_file)?;

    // try every backend that may hold a secret, even if an earlier one fails
    let age_res = Backend::Age.clear_local_secret(paths);
    let keyring_res =
        if state.is_some_and(|s| s.backend() == Backend::OSKeyring) {
            Backend::OSKeyring.clear_local_secret(paths)
        } else {
            Ok(())
        };
    age_res
        .and(keyring_res)
        .context("failed to remove the PIN's local secret")
}

pub fn status(paths: &Paths) -> String {
    if !is_registered(paths) {
        return "PIN: not set".to_string();
    }
    match load_state(paths) {
        Ok(state) => format!(
            "PIN: set\nBackend: {}\nEmpty PIN: {}",
            state.backend(),
            state.empty_pin()
        ),
        Err(e) => format!("PIN: invalid ({e:#})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::locked::Vec;
    use crate::pin::backend::age::tests::TEST_IDENTITY;

    fn locked(bytes: &[u8]) -> Vec {
        let mut vec = Vec::new();
        vec.extend(bytes.iter().copied());
        vec
    }

    fn setup() -> (tempfile::TempDir, Paths, PinBackendConfig) {
        let dir = tempfile::tempdir().unwrap();
        let identity_file = dir.path().join("identity.txt");
        std::fs::write(&identity_file, TEST_IDENTITY).unwrap();
        let paths = Paths {
            state_file: dir.path().join("cache/pin-state.json"),
            age_secret_file: dir.path().join("cache/pin-secret.age"),
        };
        let config = PinBackendConfig {
            enable_pin: true,
            kdf_params: crypto::Argon2Params {
                memory: 128,
                iterations: 1,
                parallelism: 1,
            },
            age_identity_file: Some(identity_file),
        };
        (dir, paths, config)
    }

    #[test]
    fn pin_register_unlock_clear() {
        let (_dir, paths, config) = setup();
        let keys = Keys::new(locked(&[7; 64]));
        let pin = Password::new(locked(b"1234"));

        register(
            &keys,
            Some(&pin),
            &config,
            Backend::Age,
            &paths,
            age::NoCallbacks,
        )
        .unwrap();
        assert!(is_registered(&paths));

        let state = load_state(&paths).unwrap();
        assert!(!state.empty_pin());
        let unlocked =
            unlock(Some(&pin), &state, &config, &paths, age::NoCallbacks)
                .unwrap();
        assert_eq!(unlocked.enc_key(), keys.enc_key());
        assert_eq!(unlocked.mac_key(), keys.mac_key());

        let wrong = Password::new(locked(b"0000"));
        assert!(unlock(
            Some(&wrong),
            &state,
            &config,
            &paths,
            age::NoCallbacks
        )
        .is_err());

        clear(&paths).unwrap();
        assert!(!paths.state_file.exists());
        assert!(!paths.age_secret_file.exists());
    }

    #[test]
    fn pin_clear_when_secret_already_gone() {
        let (_dir, paths, config) = setup();
        let keys = Keys::new(locked(&[7; 64]));
        register(
            &keys,
            None,
            &config,
            Backend::Age,
            &paths,
            age::NoCallbacks,
        )
        .unwrap();
        std::fs::remove_file(&paths.age_secret_file).unwrap();

        clear(&paths).unwrap();
        assert!(!is_registered(&paths));
        // and with nothing set at all
        clear(&paths).unwrap();
    }

    #[test]
    fn pin_register_requires_enable_pin() {
        let (_dir, paths, mut config) = setup();
        config.enable_pin = false;
        let keys = Keys::new(locked(&[7; 64]));
        assert!(register(
            &keys,
            None,
            &config,
            Backend::Age,
            &paths,
            age::NoCallbacks
        )
        .is_err());
        assert!(!is_registered(&paths));
    }
}
