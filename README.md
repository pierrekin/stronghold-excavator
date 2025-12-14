# stronghold-excavator

Extract secrets from IOTA Stronghold snapshot files.

A minimal, read-only Rust tool for decrypting and extracting data from Stronghold `.stronghold` snapshot files. Supports version 3 snapshots.

## Installation

```bash
cargo install --path bin
```

Or build from source:

```bash
cargo build --release
```

## CLI Usage

```bash
# Extract with password
excavator --snapshot wallet.stronghold --password "your-password"

# Extract with 32-byte hex key
excavator --snapshot wallet.stronghold --key "abc123..."

# Pretty print output
excavator --snapshot wallet.stronghold --password "your-password" --pretty

# Save to file
excavator --snapshot wallet.stronghold --password "your-password" --output secrets.json
```

Output is JSON containing all clients, vaults, records, and store entries.

## Library Usage

```rust
use stronghold_excavator::Excavator;

// Open with password
let excavator = Excavator::open_with_password("wallet.stronghold", b"password")?;

// Or with a 32-byte key
let excavator = Excavator::open("wallet.stronghold", &key)?;

// List clients
for client_id in excavator.clients() {
    // List vaults
    for vault_id in excavator.vaults(client_id)? {
        // Extract secrets
        for record_id in excavator.records(client_id, vault_id)? {
            let secret = excavator.extract_secret(client_id, vault_id, record_id)?;
            println!("{:?}: {:?}", secret.hint, secret.as_str());
        }
    }
}

// Or extract everything at once
let secrets = excavator.extract_all(client_id)?;
```

## License

MIT
