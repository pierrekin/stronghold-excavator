// Create a test Stronghold snapshot using the real Stronghold crate
// This writes test data that we can then extract with stronghold-excavator
//
// Usage: cargo run --example create_test_snapshot -- <output_path> <password>

use iota_stronghold::{KeyProvider, Location, SnapshotPath, Stronghold};
use zeroize::Zeroizing;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} <output_path> <password>", args[0]);
        std::process::exit(1);
    }

    let output_path = &args[1];
    let password = &args[2];

    println!("Creating test Stronghold snapshot at: {}", output_path);

    // Create a new Stronghold instance
    let stronghold = Stronghold::default();

    // Create a client
    let client = stronghold.create_client("test-client")?;

    // Define some test secrets to store
    let secrets: Vec<(&str, &str, Vec<u8>)> = vec![
        ("vault1", "secret1", b"Hello, World!".to_vec()),
        ("vault1", "secret2", b"This is a test secret".to_vec()),
        ("vault2", "private-key", vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                       0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                                       0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                                       0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20]),
        ("vault2", "seed", b"quick horse battery staple".to_vec()),
    ];

    // Write each secret
    for (vault_path, record_path, data) in &secrets {
        let location = Location::generic(*vault_path, *record_path);
        let vault = client.vault(*vault_path);
        vault.write_secret(location, Zeroizing::new(data.clone()))?;
        println!("  Wrote: {}/{} ({} bytes)", vault_path, record_path, data.len());
    }

    // Also write something to the store
    client.store().insert(b"config-key".to_vec(), b"config-value".to_vec(), None)?;
    println!("  Wrote store entry: config-key -> config-value");

    // Create key provider from password
    let key_provider = KeyProvider::with_passphrase_hashed_blake2b(password.as_bytes().to_vec())?;

    // Save the snapshot
    let snapshot_path = SnapshotPath::from_path(output_path);
    stronghold.commit_with_keyprovider(&snapshot_path, &key_provider)?;

    println!("\nSnapshot saved successfully!");
    println!("\nTo extract with excavator:");
    println!("  cargo run --example extract_snapshot -- {} {}", output_path, password);

    Ok(())
}
