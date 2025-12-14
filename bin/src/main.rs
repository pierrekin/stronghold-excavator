use clap::Parser;
use serde::Serialize;
use std::path::PathBuf;
use stronghold_excavator::{Excavator, ExcavatorError, ExtractedSecret};

#[derive(Parser)]
#[command(name = "excavator")]
#[command(about = "Extract secrets from Stronghold snapshot files", long_about = None)]
struct Cli {
    /// Path to the Stronghold snapshot file
    #[arg(short, long)]
    snapshot: PathBuf,

    /// Password for the snapshot
    #[arg(short, long, conflicts_with = "key")]
    password: Option<String>,

    /// 32-byte hex key (alternative to password)
    #[arg(short, long, conflicts_with = "password")]
    key: Option<String>,

    /// Output file path (defaults to stdout)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Pretty print JSON output
    #[arg(long, default_value = "false")]
    pretty: bool,
}

#[derive(Serialize)]
struct VaultDump {
    vault_id: String,
    secrets: Vec<ExtractedSecret>,
}

#[derive(Serialize)]
struct ClientDump {
    client_id: String,
    vaults: Vec<VaultDump>,
    store: Vec<StoreEntry>,
}

#[derive(Serialize)]
struct StoreEntry {
    key: String,
    value: String,
}

#[derive(Serialize)]
struct SnapshotDump {
    clients: Vec<ClientDump>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let excavator = open_snapshot(&cli)?;
    let dump = extract_all(&excavator)?;

    let json = if cli.pretty {
        serde_json::to_string_pretty(&dump)?
    } else {
        serde_json::to_string(&dump)?
    };

    match cli.output {
        Some(path) => std::fs::write(path, json)?,
        None => println!("{}", json),
    }

    Ok(())
}

fn open_snapshot(cli: &Cli) -> Result<Excavator, ExcavatorError> {
    if let Some(password) = &cli.password {
        Excavator::open_with_password(&cli.snapshot, password.as_bytes())
    } else if let Some(key_hex) = &cli.key {
        let key_bytes = hex::decode(key_hex)
            .map_err(|_| ExcavatorError::InvalidKeyLength(0))?;
        let key: [u8; 32] = key_bytes
            .try_into()
            .map_err(|v: Vec<u8>| ExcavatorError::InvalidKeyLength(v.len()))?;
        Excavator::open(&cli.snapshot, &key)
    } else {
        eprintln!("Error: either --password or --key must be provided");
        std::process::exit(1);
    }
}

fn extract_all(excavator: &Excavator) -> Result<SnapshotDump, ExcavatorError> {
    let mut clients = Vec::new();

    for client_id in excavator.clients() {
        let mut vaults = Vec::new();

        for vault_id in excavator.vaults(client_id)? {
            let mut secrets = Vec::new();

            for record_id in excavator.records(client_id, vault_id)? {
                match excavator.extract_secret(client_id, vault_id, record_id) {
                    Ok(secret) => secrets.push(secret),
                    Err(e) => {
                        eprintln!("Warning: failed to extract {:?}: {}", record_id, e);
                    }
                }
            }

            vaults.push(VaultDump {
                vault_id: hex::encode(&vault_id.0 .0),
                secrets,
            });
        }

        let store = excavator
            .get_store(client_id)?
            .iter()
            .map(|(k, v)| StoreEntry {
                key: String::from_utf8_lossy(k).to_string(),
                value: match std::str::from_utf8(v) {
                    Ok(s) => s.to_string(),
                    Err(_) => hex::encode(v),
                },
            })
            .collect();

        clients.push(ClientDump {
            client_id: hex::encode(&client_id.0 .0),
            vaults,
            store,
        });
    }

    Ok(SnapshotDump { clients })
}
