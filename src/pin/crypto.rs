/*
This module implements cryptography operations relating to the PIN feature.

PIN cryptography: derive a key-encryption key (KEK) from a user PIN and use it
to wrap the user's symmetric vault key.

# Overview
A KEK is derived using Argon2id from:
- the user PIN (may be empty),
- a device-local secret (`local_secret`) mixed in as the Argon2 "secret",
- a random salt,
- and Argon2 parameters from the config.

The derived KEK (32 bytes) is then used with XChaCha20-Poly1305 to wrap the
user key (`enc_key || mac_key`). The associated data binds the wrapped key to
the profile, and is recomputed at unwrap time rather than read from disk.

Only the user key is wrapped. The private key and organization keys are
decrypted from the local database on every unlock, exactly as with a master
password unlock, so they can't go stale, and a wrapped key that doesn't belong
to the database is rejected by the database's own MAC.

# Threat model / security properties
- Protects the user key at rest against an attacker who reads storage but does
  not know the PIN.
- The `local_secret` device-binds the KDF input. Offline guessing is
  infeasible without it.
*/
use crate::error::{Error, Result};
use crate::locked::{Keys, Password, Vec};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2,
};
use chacha20poly1305::{
    aead::{AeadCore as _, KeyInit as _},
    AeadInPlace as _, XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};

pub const KEK_LEN: usize = 32;
pub const LOCAL_SECRET_LEN: usize = 32;
const USER_KEY_LEN: usize = 64;

#[derive(Serialize, Deserialize, Clone)]
pub struct WrappedKey {
    #[serde(with = "base64")]
    ciphertext: std::vec::Vec<u8>,
    #[serde(with = "base64")]
    nonce: [u8; 24],
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(default)]
pub struct Argon2Params {
    #[serde(
        rename = "argon2_memory",
        skip_serializing_if = "Argon2Params::is_default_memory"
    )]
    pub memory: u32,
    #[serde(
        rename = "argon2_iterations",
        skip_serializing_if = "Argon2Params::is_default_iterations"
    )]
    pub iterations: u32,
    #[serde(
        rename = "argon2_parallelism",
        skip_serializing_if = "Argon2Params::is_default_parallelism"
    )]
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory: 64 * 1024,
            iterations: 3,
            parallelism: 4,
        }
    }
}

// these settings live in the main config file, so only write them out when
// they've been changed
impl Argon2Params {
    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn is_default_memory(v: &u32) -> bool {
        *v == Self::default().memory
    }

    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn is_default_iterations(v: &u32) -> bool {
        *v == Self::default().iterations
    }

    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn is_default_parallelism(v: &u32) -> bool {
        *v == Self::default().parallelism
    }

    fn to_params(&self) -> Result<argon2::Params> {
        argon2::Params::new(
            self.memory,
            self.iterations,
            self.parallelism,
            Some(KEK_LEN),
        )
        .map_err(|_| Error::Argon2)
    }
}

pub fn generate_salt() -> SaltString {
    SaltString::generate(&mut OsRng)
}

pub fn generate_local_secret() -> Vec {
    use argon2::password_hash::rand_core::RngCore as _;

    let mut buf = Vec::new();
    buf.extend(std::iter::repeat_n(0, LOCAL_SECRET_LEN));
    OsRng.fill_bytes(buf.data_mut());
    buf
}

pub fn derive_kek(
    pin: Option<&Password>,
    local_secret: &Vec,
    salt: &SaltString,
    kdf_params: &Argon2Params,
) -> Result<Vec> {
    let argon2 = Argon2::new_with_secret(
        local_secret.data(),
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        kdf_params.to_params()?,
    )
    .map_err(|_| Error::Argon2)?;

    let mut kek = Vec::new();
    kek.extend(std::iter::repeat_n(0, KEK_LEN));
    argon2
        .hash_password_into(
            pin.map_or(&[], Password::password),
            salt.as_str().as_bytes(),
            kek.data_mut(),
        )
        .map_err(|_| Error::Argon2)?;

    Ok(kek)
}

fn cipher(kek: &Vec) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(kek.data()).map_err(|_| {
        Error::PinError {
            message: "key-encryption key has the wrong length".to_string(),
        }
    })
}

fn associated_data(profile: &str) -> std::vec::Vec<u8> {
    format!("rbw-pin-wrapped-key|profile={profile}").into_bytes()
}

pub fn wrap_key(kek: &Vec, keys: &Keys, profile: &str) -> Result<WrappedKey> {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let mut buf = Vec::new();
    buf.extend(keys.enc_key().iter().copied());
    buf.extend(keys.mac_key().iter().copied());
    cipher(kek)?
        .encrypt_in_place(&nonce, &associated_data(profile), &mut buf)
        .map_err(|e| Error::PinError {
            message: e.to_string(),
        })?;

    Ok(WrappedKey {
        ciphertext: buf.data().to_vec(),
        nonce: nonce.into(),
    })
}

pub fn unwrap_key(
    kek: &Vec,
    wrapped: &WrappedKey,
    profile: &str,
) -> Result<Keys> {
    let mut buf = Vec::new();
    buf.extend(wrapped.ciphertext.iter().copied());
    cipher(kek)?
        .decrypt_in_place(
            &XNonce::from(wrapped.nonce),
            &associated_data(profile),
            &mut buf,
        )
        .map_err(|_| Error::IncorrectPassword {
            message: "incorrect PIN".to_string(),
        })?;

    if buf.data().len() != USER_KEY_LEN {
        return Err(Error::PinError {
            message: "unwrapped key has the wrong length".to_string(),
        });
    }
    Ok(Keys::new(buf))
}

// Enables serde to (de)serialize with base64
mod base64 {
    use serde::{Deserialize as _, Deserializer, Serialize as _, Serializer};

    pub fn serialize<S: Serializer, T: AsRef<[u8]>>(
        v: &T,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        crate::base64::encode(v).serialize(s)
    }

    pub fn deserialize<'de, D, T>(d: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: TryFrom<Vec<u8>>,
    {
        let encoded = String::deserialize(d)?;
        let bytes = crate::base64::decode(encoded.as_bytes())
            .map_err(serde::de::Error::custom)?;
        T::try_from(bytes)
            .map_err(|_| serde::de::Error::custom("wrong number of bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locked(bytes: &[u8]) -> Vec {
        let mut vec = Vec::new();
        vec.extend(bytes.iter().copied());
        vec
    }

    fn fast_params() -> Argon2Params {
        Argon2Params {
            memory: 128,
            iterations: 1,
            parallelism: 1,
        }
    }

    fn kek(pin: &[u8], local_secret: &[u8], salt: &SaltString) -> Vec {
        derive_kek(
            Some(&Password::new(locked(pin))),
            &locked(local_secret),
            salt,
            &fast_params(),
        )
        .unwrap()
    }

    #[test]
    fn pin_wrap_unwrap() {
        let key_content = [7_u8; USER_KEY_LEN];
        let keys = Keys::new(locked(&key_content));
        let salt = generate_salt();

        let wrapped =
            wrap_key(&kek(b"1234", &[0; 32], &salt), &keys, "rbw").unwrap();
        let unwrapped =
            unwrap_key(&kek(b"1234", &[0; 32], &salt), &wrapped, "rbw")
                .unwrap();

        assert_eq!(unwrapped.enc_key(), keys.enc_key());
        assert_eq!(unwrapped.mac_key(), keys.mac_key());
    }

    #[test]
    fn pin_unwrap_rejects_wrong_inputs() {
        let keys = Keys::new(locked(&[7; USER_KEY_LEN]));
        let salt = generate_salt();
        let wrapped =
            wrap_key(&kek(b"1234", &[0; 32], &salt), &keys, "rbw").unwrap();

        let wrong_pin = kek(b"4321", &[0; 32], &salt);
        assert!(unwrap_key(&wrong_pin, &wrapped, "rbw").is_err());

        let wrong_secret = kek(b"1234", &[1; 32], &salt);
        assert!(unwrap_key(&wrong_secret, &wrapped, "rbw").is_err());

        let right = kek(b"1234", &[0; 32], &salt);
        assert!(unwrap_key(&right, &wrapped, "other-profile").is_err());
    }

    #[test]
    fn pin_argon2_params_partial_config() {
        let params: Argon2Params =
            serde_json::from_str(r#"{"argon2_memory": 1024}"#).unwrap();
        assert_eq!(
            params,
            Argon2Params {
                memory: 1024,
                ..Argon2Params::default()
            }
        );
    }
}
