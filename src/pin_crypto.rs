// #![cfg(feature = "pin")]
/*
This module implements cryptography operations relating to the PIN feature.

In particular,

*/
use argon2::{
    Argon2,
    password_hash::{
    rand_core::OsRng,
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    }
};
use crate::locked::{ Vec as LockedVec, Keys };
use crate::error::{ Result, Error };

use chacha20poly1305::{aead::{Buffer, Aead, AeadCore, KeyInit }, AeadInPlace, ChaCha20Poly1305, Nonce};
use rustix::path::Arg;
use zeroize::{Zeroize, Zeroizing};
// TODO
// How to check if PIN is set?
// Can't be config, will have to be something from the agent state right?
// But then if agent is killed, do we really want the pin to be cleared?
// So maybe we do:
//   - Check if pin is set in config
//   - Check if there is an encrypted local secret for the pin (in practice if there is an age file?)
//   - If both are there then we go for it and unlock
// Alternatives:
//    - DB -- I think this is a no go, since it's updated from API and live's in agent state(?)
//    - State -- Doesn't persist after reboot
//    -

// TODO build a map of where this fits ino the codebase
//
// So we have the agent and the client
// -- Agent
//  Holds the keys in memory
//  Encrypts the dek when you lock it -- WRONG, it simply clears the key, never writes the encrypted to disk!
//      -- We are writing the encrypted symmetric key to disk :-O (is this crazy or is it ok?)
//  Decrypts the dek when you unlock it -- decrypt_locked_symmetric so we need to keep the key in identity.keys
//  unlock_state get's the input from the user

// -- Client
//  Can make requests to the agent
//
//
// When Identity::new is called the `enc_key` is derived

// TODO change pin to Vec
// TODO this doesn't need to output to a Keys, only some Vec
// TODO Figure out what is happening with the hmac stuff in Identity::new
fn derive_key_from_pin(pin: Option<LockedVec>, local_secret: LockedVec) -> Result<LockedVec> { // TODO change result type to Vec

    let argon2_config = Argon2::new_with_secret(
        local_secret.data(),
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new( // TODO find a good argon2 config
            64 * 1024,
            2,
            2,
            Some(32)
        ).map_err(|_| Error::Argon2)?
    ).map_err(|_| Error::Argon2)?; // TODO clean this up


    let mut pin_key = LockedVec::new();
    pin_key.extend(std::iter::repeat_n(0, 32));

    let salt = SaltString::generate(&mut OsRng); // TODO this should be imported from metadata associated to the pin
                                                           //

    Argon2::hash_password_into(
        &argon2_config,
        pin.as_ref()
            .map(|pin| pin.data())
            .unwrap_or(&[]), // TODO have config that dissallows empty pin
                                      // TODO there seems to be a bug on empty input to argon, so need to provide a default value
                                      // TODO put profile in here?
        &salt.as_str().as_bytes(),
        &mut pin_key.data_mut()
    ).map_err(|_| Error::Argon2)?;

    Ok(pin_key)
}

// Given the pin and the local_secret (age / keyring) encrypt the dek
// TODO Can I get away with passing arguments by reference?
fn wrap_dek(pin_key: LockedVec, keys: Keys) -> Result<(Vec<u8>, Nonce)> {
    let cipher = ChaCha20Poly1305::new_from_slice(pin_key.data())
        .map_err(|_| Error::ChaChaEncryption)?; // TODO handle error
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message

    let ciphertext = {
        let mut buf = LockedVec::new();
        buf.extend(keys.enc_key().iter().copied());
        buf.extend(keys.mac_key().iter().copied());

        cipher.encrypt_in_place(&nonce, b"", &mut buf)
            .map_err(|_| Error::ChaChaEncryption)?;

        buf.data().to_vec()
    };

    Ok((ciphertext, nonce))
}

// Need to implement the below traits for Vec in order to avoid allocating secrets
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
        self.truncate(len)
    }

}

fn unwrap_dek(pin_key: LockedVec, wrapped_dek: Vec<u8>, nonce: Nonce) -> Result<Keys> {
    let cipher = ChaCha20Poly1305::new_from_slice(pin_key.data()).unwrap(); // TODO handle error

    let mut key = LockedVec::new();
    key.extend(wrapped_dek.into_iter());

    cipher.decrypt_in_place(
        &nonce,
        b"",
        &mut key
    ).map_err(|_| Error::PinKekDecryption)?;

    Ok(Keys::new(key))
}

// fn wrap_dek() -- We don't do this in bitwarden, because the wrapped dek is in the database from bitwarden I believe...
// So how do we keep the PIN wrapped dek around... Well we can just put it algonside the wrapped dek
// Where is that kept ? Probably in the DB? No because that's the bitwarden database :thinking:
    // Yes it's kept in the db, so we need to add the call to the pin for unlock_state, but that doesn't take any PIN paremeters right now
    // So either
        // Pass in a PinState struct with backend, protected key_file
        // access config values? (I don't think this makes much sense)

#[cfg(test)]
mod tests {
    use textwrap::wrap;
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
        let key_content = [48u8; 64];
        let dek = Keys::new(create_vec(&key_content));

        let pin = create_vec(b"1234".as_ref());
        let local_secret = create_vec("0000".as_ref());
        let derived_kek = derive_key_from_pin(Some(pin), local_secret).unwrap();

        let (wrapped_dek, nonce) = wrap_dek(derived_kek.clone(), dek).unwrap();

        let key_to_test = unwrap_dek(derived_kek, wrapped_dek, nonce).unwrap();

        let key_to_test_raw = concat_key_bytes(key_to_test.enc_key(), key_to_test.mac_key());
        assert_eq!(key_to_test_raw.as_slice(), &key_content)
    }
}