use sha3::{Digest, Sha3_512};
use base64::{engine::general_purpose, Engine as _};
use base64::decode;
use subtle::ConstantTimeEq;
use std::fs::File;
use std::io::{self, BufReader, Read, Write};

fn sha3_512_file(path: &str) -> io::Result<[u8; 64]> {
    let mut f = File::open(path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;

    let mut hasher = Sha3_512::new();
    hasher.update(&buf);
    let digest = hasher.finalize();

    let mut out = [0u8; 64];
    out.copy_from_slice(&digest[..]);
    Ok(out)
}

fn main() -> Result<(), Box<dyn std::error::Error>>{
    // Precompute target hash once.
    let file = File::open("test.txt")?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha3_512::new();

    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }

    let digest = hasher.finalize(); // 64 bytes
    // let b64 = general_purpose::STANDARD.encode(digest);

    // Base64 length should be 88 chars for a 64-byte digest.
    println!("Sha3-512: {:?}", digest);
    println!("Sha3-512 Base64 code: {}", general_purpose::STANDARD.encode(digest));
    // println!("📄 SHA3-512(test.txt) in Base64 = {}", expected_b64);
    println!("Type 'exit' to quit.\n");

    // --- Input loop ---
    loop {
        print!("b64> ");
        io::stdout().flush().unwrap();

        let mut line = String::new();
        if io::stdin().read_line(&mut line).is_err() {
            eprintln!("⚠️  Input error. Try again.");
            continue;
        }

        let input = line.trim();
        if input.eq_ignore_ascii_case("exit") {
            println!("Exit.");
            break Ok(());
        }
        if input.is_empty() {
            eprintln!("⚠️  Empty input. Try again.");
            continue;
        }

        // --- Parse Base64 ---
        let decoded = match general_purpose::STANDARD.decode(input) {
            Ok(b) => b,
            Err(_) => {
                eprintln!("❌ Invalid Base64 format. Try again.");
                continue;
            }
        };

        // --- Constant-time verification ---
        let ok = if decoded.len() == 64 {
            decoded.ct_eq(&digest).unwrap_u8() == 1
        } else {
            false
        };

        if ok {
            println!("✅ Match: input equals SHA3-512(test.txt).");
        } else {
            println!("❌ No match.");
        }
    }
}
