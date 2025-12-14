// Example: Extract secrets from a Stronghold snapshot
//
// Usage: cargo run --example extract -- <snapshot_path> <password_or_key>
//
// If the second argument is 64 hex characters, it's treated as a raw key.
// Otherwise, it's treated as a password and hashed with Blake2b.

use stronghold_excavator::Excavator;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} <snapshot_path> <password_or_hex_key>", args[0]);
        eprintln!();
        eprintln!("If the key is 64 hex characters, it's used directly.");
        eprintln!("Otherwise, it's treated as a password and hashed with Blake2b.");
        std::process::exit(1);
    }

    let path = &args[1];
    let key_or_password = &args[2];

    // Try to parse as hex key first
    let excavator = if key_or_password.len() == 64 {
        match hex::decode(key_or_password) {
            Ok(key_bytes) if key_bytes.len() == 32 => {
                let key: [u8; 32] = key_bytes.try_into().unwrap();
                println!("Using provided hex key");
                Excavator::open(path, &key)
            }
            _ => {
                println!("Using password (hashed with Blake2b)");
                Excavator::open_with_password(path, key_or_password.as_bytes())
            }
        }
    } else {
        println!("Using password (hashed with Blake2b)");
        Excavator::open_with_password(path, key_or_password.as_bytes())
    };

    let excavator = match excavator {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Failed to open snapshot: {}", e);
            std::process::exit(1);
        }
    };

    println!();
    println!("=== Snapshot Contents ===");
    println!();

    for client_id in excavator.clients() {
        println!("Client: {:?}", client_id);

        // List vaults
        match excavator.vaults(client_id) {
            Ok(vaults) => {
                for vault_id in vaults {
                    println!("  Vault: {:?}", vault_id);

                    // List records
                    match excavator.records(client_id, vault_id) {
                        Ok(records) => {
                            for record_id in records {
                                print!("    Record: {:?}", record_id);

                                // Try to extract
                                match excavator.extract_secret(client_id, vault_id, record_id) {
                                    Ok(secret) => {
                                        match secret.hint.as_str() {
                                            Some(hint) => println!(" [hint: {}]", hint),
                                            None => println!(),
                                        }

                                        // Print data
                                        if let Some(s) = secret.as_str() {
                                            if s.len() <= 100 {
                                                println!("      Data (UTF-8): {}", s);
                                            } else {
                                                println!("      Data (UTF-8, truncated): {}...", &s[..100]);
                                            }
                                        } else {
                                            let hex = secret.as_hex();
                                            if hex.len() <= 100 {
                                                println!("      Data (hex): {}", hex);
                                            } else {
                                                println!("      Data (hex, truncated): {}...", &hex[..100]);
                                            }
                                        }
                                        println!("      Length: {} bytes", secret.data.len());
                                    }
                                    Err(e) => {
                                        println!(" [ERROR: {}]", e);
                                    }
                                }
                            }
                        }
                        Err(e) => println!("    Error listing records: {}", e),
                    }
                }
            }
            Err(e) => println!("  Error listing vaults: {}", e),
        }

        // Show store contents
        match excavator.get_store(client_id) {
            Ok(store) if !store.is_empty() => {
                println!("  Store ({} entries):", store.len());
                for (key, value) in store {
                    let key_str = String::from_utf8_lossy(key);
                    let value_preview = if value.len() <= 50 {
                        hex::encode(value)
                    } else {
                        format!("{}... ({} bytes)", hex::encode(&value[..25]), value.len())
                    };
                    println!("    {} -> {}", key_str, value_preview);
                }
            }
            _ => {}
        }

        println!();
    }
}
