#[cfg(feature = "pin")]
/*
    rbw pin clear     => rbw::pin_flow::clear_pin(...)
    rbw pin set       => rbw::pin_flow::register(...
    rbw pin status    => rbw::pin_flow::status(...)
*/

#[derive(Debug, clap::Parser)]
pub enum Pin {
    #[command(about = "Set up the PIN for local unlock")]
    Set {
        #[arg(
            long,
            default_value_t = false,
            // help = "Whether to have an empty pin. Only recommended for a device bound local secret with user input (e.g hardware key, mac touchid)"
        )]
        /// Whether to allow using an empty pin.
        ///
        /// Only recommended for a device and user input bound local secret (e.g yubikey, mac touchid)
        /// The age backend with the plugins `yubikey, se`
        empty_pin: bool,
        #[arg(long, value_enum, help = "Backend to store local_secret")] // TODO this NEEDS to be an enum value
        backend: crate::pin::backend::Backend,
    },
    #[command(about = "Clear the PIN")]
    Clear,

    #[command(about = "Show status of PIN")]
    Status
}

impl Pin {
    pub fn subcommand_name(&self) -> String {
        match self {
            Self::Set { .. } => "set",
            Self::Status     => "status",
            Self::Clear      => "clear",
        }
            .to_string()
    }
}
