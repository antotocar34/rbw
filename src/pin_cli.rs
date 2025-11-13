#[cfg(feature = "pin")]
/*
    rbw pin clear     => rbw::pin_flow::clear_pin(...)
    rbw pin set       => rbw::pin_flow::register(...
    rbw pin status    => rbw::pin_flow::status(...)
*/

#[derive(Debug, clap::Parser)]
pub enum Pin {
    #[command(about = "Set up the PIN for local unlock")]
    Set,
    // {
    //     #[arg(help = "Backend to store local_secret")]
    //     backend: String,
    //     #[arg(help = "Whether to have an empty pin. Only recommended for a device bound key with user input (e.g hardware key, mac touchid)")]
    //     // empty: bool
    // },
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
