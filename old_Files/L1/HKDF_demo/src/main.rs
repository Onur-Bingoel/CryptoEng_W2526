mod crypto;
mod io;

use base64::{engine::general_purpose, Engine as _};
use crypto::hkdf_demo::derive_aes256gcm_key;
use hex::encode;

fn main() -> std::io::Result<()> {
    println!("HKDF (SHA3-256) → derive AES-256-GCM key\n");

    let seed = io::readline::read_line_prompt("Seed (IKM)> ")?;
    let salt = io::readline::read_line_prompt("Salt (optional, empty = none)> ")?;
    let info = io::readline::read_line_prompt("Aux input (info)> ")?;

    let salt_opt = if salt.is_empty() { None } else { Some(salt.as_bytes()) };

    let key = match derive_aes256gcm_key(seed.as_bytes(), salt_opt, info.as_bytes()) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("HKDF error: {e}");
            std::process::exit(1);
        }
    };

    println!("\nDerived AES-256-GCM key (32 bytes):");
    println!("  Base64 format: {}", general_purpose::STANDARD.encode(&key));
    println!("  Hex format: {}", hex::encode(&key));

    Ok(())
}