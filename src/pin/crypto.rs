#![cfg(feature = "pin")]
/*
This module implements cryptography operations relating to the PIN feature.
Refer to the design document for an overview of the design of the feature




*/
use std::collections::HashMap;
use argon2::{
    Argon2,
    password_hash::{
    rand_core::OsRng,
    SaltString
    }
};
use crate::locked::{Vec as LockedVec, Keys, Password};
use crate::error::{ Result, Error };

use chacha20poly1305::{
    aead::{Buffer, AeadCore, KeyInit},
    AeadInPlace,
    ChaCha20Poly1305,
    Nonce,

};
use serde::{Serialize, Deserialize};

pub const KEK_LEN: usize = 32;

#[derive(Serialize, Deserialize, Clone)]
pub struct WrappedKey {
    #[serde(with = "base64")]
    wrapped_keys: Vec<u8>,
    #[serde(with = "base64")]
    nonce: [u8; 12],
    // Bind the key to the correct profile
    context: String
}

impl WrappedKey {
    pub fn bytes(&self) -> &[u8] {
       self.wrapped_keys.as_slice()
    }
    pub fn new(wrapped_keys: Vec<u8>, nonce: Nonce, context: String) -> Self {
        Self {
            wrapped_keys,
            nonce: (*nonce.as_slice()).try_into().unwrap(), // Nonce is effectively defined to be a [u8; 12]
            context
        }
    }
    fn nonce(&self) -> Nonce {
        (self.nonce).into()
    }
}


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Argon2Params {
    #[serde(rename="argon2_memory")]
    pub memory: u32,
    #[serde(rename="argon2_iterations")]
    pub iterations: u32,
    #[serde(rename="argon2_parallelism")]
    pub parallelism: u32
}

impl Argon2Params {
    pub fn new() -> Self {
        Self {
            memory: 64 * 1024,
            iterations: 3,
            parallelism: 4
        }
    }
    pub fn to_params(&self) -> Result<argon2::Params> {
        argon2::Params::new(
            self.memory,
            self.iterations,
            self.parallelism,
            Some(KEK_LEN) // Size of the derived key
        ).map_err(|_| Error::Argon2)
    }
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::new()
    }
}

pub fn derive_kek_from_pin(
    pin: Option<&Password>,
    local_secret: &LockedVec,
    salt: &SaltString,
    kdf_params: &Argon2Params
) -> Result<LockedVec> {

    let argon2_config = Argon2::new_with_secret(
        local_secret.data(),
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        kdf_params.to_params()?
    ).map_err(|_| Error::Argon2)?;


    let mut pin_key = LockedVec::new();
    pin_key.extend(std::iter::repeat_n(0, KEK_LEN));


    Argon2::hash_password_into(
        &argon2_config,
        pin.as_ref()
            .map_or(&[], |pin| pin.password()),
        salt.as_str().as_bytes(),
        pin_key.data_mut()
    ).map_err(|_| Error::Argon2)?;

    Ok(pin_key)
}

fn wrap_single_key(cipher: &ChaCha20Poly1305, keys: &Keys, context: &String) -> Result<WrappedKey> {

    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message

    let ciphertext = {
        let mut buf = LockedVec::new();
        buf.extend(keys.enc_key().iter().copied());
        buf.extend(keys.mac_key().iter().copied());

        cipher.encrypt_in_place(&nonce, context.as_bytes(), &mut buf)
            .map_err(|e| Error::PinError {message: e.to_string()})?;

        buf.data().to_vec()
    };

    Ok(WrappedKey::new(ciphertext, nonce, context.to_owned()))
}
// Given the pin and the local_secret (age / keyring) encrypt the dek
pub fn wrap_dek(
    pin_key: &LockedVec,
    keys: &Keys,
    org_keys: &HashMap<String, Keys>
) -> Result<(WrappedKey, HashMap<String, WrappedKey>)> {
    let cipher = ChaCha20Poly1305::new_from_slice(pin_key.data())
        .map_err(|e| Error::PinError {message: "Kek has invalid length".to_string()})?;

    let context_string = format!("pin-wrapped-dek|profile={}", crate::dirs::profile());
    let wrapped_keys = wrap_single_key(&cipher, keys, &context_string)?;

    let wrapped_org_keys: HashMap<String, WrappedKey> = org_keys
        .iter()
        .map(|(org, k)| {
            let context_string_org = format!("{}|org={}",context_string.clone(), org.as_str());
            wrap_single_key(&cipher, k, &context_string_org).map(|wk| (org.clone(), wk))
        })
        .collect::<std::result::Result<_, Error>>()?;

    Ok((wrapped_keys, wrapped_org_keys))
}

// Need to implement the below traits
// in order to decrypt in place (to not have to allocate secret to an insecure buffer)
impl AsRef<[u8]> for LockedVec {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

impl AsMut<[u8]> for LockedVec {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data_mut()
    }
}
impl Buffer for LockedVec {
    fn extend_from_slice(&mut self, other: &[u8]) -> chacha20poly1305::aead::Result<()> {
        self.extend(other.iter().copied());
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.truncate(len);
    }
}

fn unwrap_single_key(cipher: &ChaCha20Poly1305, wrapped_keys: &WrappedKey) -> Result<Keys> {
    let mut key = LockedVec::new();
    key.extend(wrapped_keys.bytes().to_vec().into_iter());

    cipher.decrypt_in_place(
        &wrapped_keys.nonce(),
        wrapped_keys.context.as_bytes(),
        &mut key
    ).map_err(|_| Error::PinError {message: "Decryption error".to_string() })?;

    Ok(Keys::new(key))
}
pub fn unwrap_dek(pin_key: &LockedVec, wrapped_keys: &WrappedKey, wrapped_org_keys: &HashMap<String, WrappedKey>) -> Result<(Keys, HashMap<String, Keys>)> {
    let cipher = ChaCha20Poly1305::new_from_slice(pin_key.data())
        .map_err(|_| Error::PinError {message: "invalid keylen; couldn't initialize chacha20poly1305 cipher".into() })?;

    let keys = unwrap_single_key(&cipher, wrapped_keys)?;

    let wrapped_org_keys: HashMap<String, Keys> = wrapped_org_keys
        .iter()
        .map(|(org, k)| {
            unwrap_single_key(&cipher, k).map(|wk| (org.clone(), wk))
        })
        .collect::<std::result::Result<_, Error>>()?;

    Ok((keys, wrapped_org_keys))
}

// Enables serde to (de)serialize with base64
mod base64 {
    use serde::{Serialize, Deserialize};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer, T: AsRef<[u8]>>(v: &T, s: S) -> Result<S::Ok, S::Error> {
        let base64 = crate::base64::encode(v);
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D, T>(d: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: TryFrom<Vec<u8>>
    {
        let base64 = String::deserialize(d)?;

        let bytes: Vec<u8> = crate::base64::decode(base64.as_bytes())
            .map_err(serde::de::Error::custom)?;

        T::try_from(bytes)
            .map_err(
                |_e| serde::de::Error::custom("Error deserializing pin state")
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_vec(bytes: &[u8]) -> LockedVec {
        let mut vec = LockedVec::new();
        vec.extend(bytes.iter().copied());
        vec
    }

    fn concat_key_bytes(a: &[u8], b: &[u8]) -> zeroize::Zeroizing<Vec<u8>> {
        let mut out = zeroize::Zeroizing::new(Vec::with_capacity(a.len() + b.len()));
        out.extend_from_slice(a);
        out.extend_from_slice(b);
        out
    }

    #[test]
    fn pin_encrypt_decrypt() {
        let key_content = [b'0'; 64];
        let dek = Keys::new(create_vec(&key_content));

        let org_keys: HashMap<String, Keys> = [("test_corp".to_string(), dek.clone())].into_iter().collect();

        let pin = Password::new(create_vec(b"1234".as_ref()));
        let local_secret = create_vec([b'0';32].as_ref());
        let salt = SaltString::generate(&mut OsRng);
        let kdf_params = Argon2Params {memory: 1024, iterations: 1, parallelism: 1};
        let derived_kek = derive_kek_from_pin(Some(&pin), &local_secret, &salt, &kdf_params).unwrap();

        let (wrapped_dek, wrapped_org_keys) = wrap_dek(&derived_kek, &dek, &org_keys).unwrap();

        let (key_to_test, org_keys_to_test) = unwrap_dek(&derived_kek, &wrapped_dek, &wrapped_org_keys).unwrap();

        let key_to_test_raw = concat_key_bytes(key_to_test.enc_key(), key_to_test.mac_key());
        assert_eq!(key_to_test_raw.as_slice(), &key_content);

        let key_to_test_raw2 = {
            let key = org_keys_to_test.get("test_corp").unwrap();
            concat_key_bytes(key.enc_key(), key.mac_key())
        };
        assert_eq!(key_to_test_raw2.as_slice(), &key_content)
    }
}