mod crypto;
mod io;

use anyhow::Result;
use std::fs;
use base64::{engine::general_purpose, Engine as _};

fn main() -> Result<()> {
    println!("X.509 Certificate Reader (type 'exit' to quit)\n");

    loop {
        // 1. Ask for input
        let path = io::readline::read_line_prompt("Certificate file (PEM or DER)> ")?;
        if path.eq_ignore_ascii_case("exit") {
            println!("Exit.");
            break;
        }

        // 2. Try to read the file
        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Cannot read file '{}': {}. Please try again.\n", path, e);
                continue;
            }
        };

        // 3. Parse and display results
        match crypto::x509_demo::parse_pem_or_der(&data) {
            Ok(certs) => {
                for (i, info) in certs {
                    println!("--- Certificate [{}] ---", i);
                    println!("Subject            : {}", info.subject);
                    println!("Issuer             : {}", info.issuer);
                    println!("Serial             : 0x{}", info.serial_hex);
                    println!("Validity           : {}  ->  {}", info.not_before, info.not_after);
                    println!("Public Key Algorithm : {}", info.pk_algorithm_name);
                    println!("Fingerprint SHA-256: {}", info.sha256_fingerprint_hex);
                    // Print the public key in PEM format
                    let b64_key = general_purpose::STANDARD.encode(&info.public_key_der);
                    println!("-----BEGIN PUBLIC KEY-----");
                    for chunk in b64_key.as_bytes().chunks(64) {
                        println!("{}", std::str::from_utf8(chunk).unwrap());
                    }
                    println!("-----END PUBLIC KEY-----\n");
                }
            }
            Err(e) => {
                eprintln!("Failed to parse '{}': {}\n", path, e);
            }
        }
    }

    Ok(())
}