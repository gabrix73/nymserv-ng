use clap::{Parser, Subcommand};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tracing::info;

use nymserv_ng::crypto::pq::generate_kem_keypair;
use nymserv_ng::store::NymStore;

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
        #[arg(short, long, default_value = "keys")]
        out_dir: String,
        #[arg(short, long, default_value = "www")]
        pub_dir: String,
    },
    /// Inspect alias status in local database
    Inspect {
        alias: String,
        #[arg(short, long, default_value = "/var/lib/nymserv/data/nymserv.redb")]
        db: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.command {
        Commands::GenKeys { out_dir, pub_dir } => {
            fs::create_dir_all(&out_dir)?;
            fs::create_dir_all(&pub_dir)?;

            info!("Generating ML-KEM-768 post-quantum keypair...");
            let (priv_key, pub_key) = generate_kem_keypair();

            let priv_path = Path::new(&out_dir).join("nymserver-pq-secret.bin");
            let pub_path = Path::new(&pub_dir).join("nymserver-pq-pubkey.bin");

            let mut f_priv = fs::File::create(&priv_path)?;
            f_priv.write_all(&priv_key)?;
            let mut perms = f_priv.metadata()?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&priv_path, perms)?;

            let mut f_pub = fs::File::create(&pub_path)?;
            f_pub.write_all(&pub_key)?;

            println!("ML-KEM-768 private key saved to: {}", priv_path.display());
            println!("ML-KEM-768 public key saved to:  {}", pub_path.display());
            println!("Public key SHA256: {}", sha256_hex(&pub_key));
        }
        Commands::Inspect { alias, db } => {
            info!("Inspecting alias '{}' in database {:?}", alias, db);
            if !db.exists() {
                anyhow::bail!("Database file does not exist at {:?}", db);
            }
            let store = NymStore::open(&db)?;
            match store.get_alias(&alias)? {
                Some(record) => {
                    println!("Alias:            {}", record.alias);
                    println!("Created at:       {}", record.created_at);
                    println!("Last active:      {}", record.last_active_at);
                    println!("Flags:            0x{:04x}", record.flags);
                    println!("Reply Blocks:     {}", record.reply_blocks.len());
                    for (i, rb) in record.reply_blocks.iter().enumerate() {
                        let lines: Vec<&str> = rb.lines().collect();
                        println!("  [#{}] {} lines (first line: '{}')", i + 1, lines.len(), lines.first().unwrap_or(&""));
                    }
                    if let Some(ref pubkey) = record.public_key_armor {
                        println!("Public Key:       Present ({} bytes)", pubkey.len());
                    } else {
                        println!("Public Key:       None");
                    }
                }
                None => {
                    println!("Alias '{}' was NOT found in database.", alias);
                }
            }
        }
    }
    Ok(())
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    let mut out = String::new();
    for b in hash {
        out.push_str(&format!("{:02x}", b));
    }
    out
}
