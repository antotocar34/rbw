/// Lets age plugins ask the user for input (e.g. a hardware token PIN)
/// through pinentry.
///
/// age calls these synchronously, so they must only be used from a blocking
/// thread (`tokio::task::spawn_blocking`), never from an async task.
#[derive(Clone)]
pub struct PinentryCallbacks {
    pinentry: String,
    environment: rbw::protocol::Environment,
    runtime: tokio::runtime::Handle,
}

impl PinentryCallbacks {
    pub fn new(
        pinentry: &str,
        environment: &rbw::protocol::Environment,
    ) -> Self {
        Self {
            pinentry: pinentry.to_string(),
            environment: environment.clone(),
            runtime: tokio::runtime::Handle::current(),
        }
    }

    fn prompt(&self, description: &str) -> Option<rbw::locked::Password> {
        self.runtime
            .block_on(rbw::pinentry::getpin(
                &self.pinentry,
                "age plugin",
                description,
                None,
                &self.environment,
                true,
            ))
            .map_err(|e| log::warn!("age plugin prompt failed: {e}"))
            .ok()
    }
}

impl age::Callbacks for PinentryCallbacks {
    fn display_message(&self, message: &str) {
        log::info!("age plugin: {message}");
    }

    fn confirm(
        &self,
        _message: &str,
        _yes_string: &str,
        _no_string: Option<&str>,
    ) -> Option<bool> {
        None
    }

    fn request_public_string(&self, description: &str) -> Option<String> {
        let input = self.prompt(description)?;
        String::from_utf8(input.password().to_vec()).ok()
    }

    fn request_passphrase(
        &self,
        description: &str,
    ) -> Option<age::secrecy::SecretString> {
        let input = self.prompt(description)?;
        String::from_utf8(input.password().to_vec())
            .ok()
            .map(age::secrecy::SecretString::from)
    }
}
