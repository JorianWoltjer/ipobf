use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(name = "ipobf", about = "A simple CLI to obfuscate IP addresses")]
pub struct Cli {
    /// The IP address to obfuscate. May also be a hostname or any of "cloud|meta|metadata" to use 169.254.169.254
    pub host: String,

    /// The amount of 0-padding to use
    #[clap(short, long, default_value = "3")]
    pub padding: usize,

    /// Disable adding few extra aliases for localhost (eg. 0.0.0.0, 127.1.2.3) and cloud (eg. [fd00:ec2::254])
    #[clap(short, long)]
    pub no_aliases: bool,

    /// Output file
    #[clap(short, long)]
    pub output: Option<PathBuf>,

    /// Append to the output file
    #[clap(short = 'a', long, requires("output"))]
    pub output_append: bool,

    /// Add brackets to IPv6 addresses
    #[clap(short, long)]
    pub brackets: bool,
}
