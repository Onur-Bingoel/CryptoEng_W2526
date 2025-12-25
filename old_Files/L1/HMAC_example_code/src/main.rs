mod crypto;
mod io;
mod utils;
use crate::crypto::hmac::{compute_hmac, verify_hmac};
use crate::io::readline::read_line;
use crate::utils::encode::decode_b64_flex;
use base64::{engine::general_purpose, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;

fn main() {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key); // sample a random key

    println!("HMAC demo — Base64 key: {}", general_purpose::STANDARD.encode(&key));

    loop {
        let msg = match read_line("\nMessage> ") {
            Ok(s) => s,
            Err(_) => { eprintln!("Input error."); continue; }
        };
        if msg.eq_ignore_ascii_case("exit") { break; }

        let tag = compute_hmac(&key, msg.as_bytes());
        println!("HMAC (Base64): {}", general_purpose::STANDARD.encode(&tag));

        let input = match read_line("Verify MAC (Base64)> ") {
            Ok(s) => s,
            Err(_) => { eprintln!("Input error."); continue; }
        };
        if input.eq_ignore_ascii_case("exit") { break; }

        let provided = match decode_b64_flex(&input) {
            Ok(b) => b,
            Err(_) => { eprintln!("Invalid Base64."); continue; }
        };

        let ok = verify_hmac(&key, msg.as_bytes(), &provided);
        println!("{}", if ok { "Valid tag" } else { "Invalid MAC tag" });
    }
}
