use clap::Parser;
use tracing::info;

use nymserv_ng::config::Config;

#[derive(Parser, Debug)]
#[command(author, version, about = "nymserv-ng Daemon: pool mixing, queue dispatch and remailer backend")]
struct Args {
    #[arg(short, long, default_value = "/etc/nymserv/nymserv.toml")]
    config: String,
}

fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    info!("Starting nymservd daemon with config {}", args.config);
    // Runs background spool worker, Poisson pool delay and outbound remailer queues
}
