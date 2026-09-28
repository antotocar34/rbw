#[derive(Debug, clap::Parser)]
pub enum Pin {
    #[command(about = "Set up the PIN for local unlock")]
    Set {
        /// Don't ask for a PIN at all.
        ///
        /// Only recommended when the local secret is bound to both the
        /// device and user presence, e.g. the age backend with the
        /// `yubikey` or `se` plugins
        #[arg(long)]
        empty_pin: bool,
        #[arg(long, value_enum, help = "Backend to store the local secret")]
        backend: rbw::pin::backend::Backend,
    },

    #[command(about = "Clear the PIN")]
    Clear,

    #[command(about = "Show status of PIN")]
    Status,
}

impl Pin {
    pub fn subcommand_name(&self) -> &'static str {
        match self {
            Self::Set { .. } => "set",
            Self::Status => "status",
            Self::Clear => "clear",
        }
    }
}
