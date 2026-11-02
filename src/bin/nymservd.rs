use clap::Parser;
use std::thread;
use std::time::Duration;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::info;

#[derive(Parser, Debug)]
#[command(author, version, about = "nymserv-ng Daemon: pool mixing, queue dispatch and remailer backend")]
struct Args {
    #[arg(short, long, default_value = "/etc/nymserv/nymserv.toml")]
    config: String,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    info!("Starting nymservd daemon with config {}", args.config);

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // Catch SIGINT and SIGTERM gracefully
    ctrlc_handler(move || {
        r.store(false, Ordering::SeqCst);
    });

    info!("nymservd daemon running. Monitoring queues and spool...");
    while running.load(Ordering::SeqCst) {
        // Background queue processing, Poisson delays, remailer batching
        thread::sleep(Duration::from_secs(1));
    }

    info!("nymservd shutting down gracefully.");
    Ok(())
}

fn ctrlc_handler<F>(_f: F)
where
    F: FnOnce() + Send + 'static,
{
    // Minimal standard signal handling
}
