use std::path::PathBuf;
use crate::locked::Vec;


struct PinBackendConfig {
    encrypted_secret_file: PathBuf
}

trait PinBackend {
    fn get_local_secret(config: PinBackendConfig) -> Vec;

}


struct AgePinBackend;

impl PinBackend for AgePinBackend {
    fn get_local_secret(config: PinBackendConfig) -> Vec {
        todo!()
    }
}