use clap::Parser;
use std::io::{self, Read};
use tracing::{info, error};

use nymserv_ng::config::Config;
use nymserv_ng::protocol::ghio::{parse_config_message, validate_alias};

#[derive(Parser, Debug)]
#[command(author, version, about = "nymserv-ng Local Delivery Agent (Postfix integration)")]
struct Args {
    #[arg(short, long, default_value = "/etc/nymserv/nymserv.toml")]
    config: String,

    #[arg(short, long)]
    recipient: Option<String>,
}

fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    info!("nymserv-lda invoked for recipient: {:?}", args.recipient);

    // Read email from stdin (provided by Postfix pipe)
    let mut input = Vec::new();
    if let Err(e) = io::stdin().read_to_end(&mut input) {
        error!("failed to read stdin: {}", e);
        std::process::exit(75); // EX_TEMPFAIL
    }

    info!("received {} bytes from stdin", input.len());
    // Process inbound email according to recipient (config, send, or user alias)
    // Return EX_OK (0) to MTA
}
