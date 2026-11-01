use clap::{Parser, Subcommand};
use tracing::info;

#[derive(Parser, Debug)]
#[command(author, version, about = "nymserv-ng Administrative CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate server keypairs (classical and post-quantum)
    GenKeys {
        #[arg(short, long, default_value = "/var/lib/nymserv/keys")]
        out_dir: String,
    },
    /// Inspect alias status in local database
    Inspect {
        alias: String,
    },
}

fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.command {
        Commands::GenKeys { out_dir } => {
            info!("Generating keys in {}", out_dir);
        }
        Commands::Inspect { alias } => {
            info!("Inspecting alias {}", alias);
        }
    }
}
