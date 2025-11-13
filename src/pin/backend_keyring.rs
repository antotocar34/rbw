#![cfg(feature = "pin")]

use crate::config::Config;
use crate::pin::backend::PinBackend;

pub struct KeyringPinBackend; // TODO figure out what to do here

impl PinBackend for KeyringPinBackend {
    fn store_local_secret(&self, kek: &crate::locked::Vec, config: &Config) -> anyhow::Result<()> {
        todo!()
    }

    fn retrieve_local_secret(&self, config: &Config) -> anyhow::Result<crate::locked::Vec> {
        todo!()
    }

    fn clear_local_secret(&self) -> anyhow::Result<()> {
        todo!()
    }
}