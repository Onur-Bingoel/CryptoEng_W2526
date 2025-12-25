mod crypto;
mod io;
mod utils;

use crate::crypto::AEADdemo::{self, Key, Nonce};
use crate::io::prompt_readline::read_line_prompt;

use base64::{engine::general_purpose, Engine as _};
use rand::{rngs::OsRng, RngCore};

fn b64e(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

fn b64d(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    // accept padded/unpadded/URL-safe; strip whitespace
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if let Ok(b) = general_purpose::STANDARD.decode(&s) { return Ok(b); }
    if let Ok(b) = general_purpose::STANDARD_NO_PAD.decode(&s) { return Ok(b); }
    if let Ok(b) = general_purpose::URL_SAFE.decode(&s) { return Ok(b); }
    general_purpose::URL_SAFE_NO_PAD.decode(&s)
}

/// AEAD demo loop following your steps:
/// (1) random key; (2) encrypt; (3) decrypt;
/// (4) tamper ciphertext; (5) tamper AD.
pub fn main() {
    println!("AEAD demo (AES-256-GCM). Type 'exit' to quit.");

    // (1) Generate random key once (for demo).
    let mut key: Key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    println!("The secret key (Base64): {}", b64e(&key));

    loop {
        // message and AD
        let msg = match read_line_prompt("\nPlaintext (in Ascii format)> ") { Ok(s) => s, Err(_) => continue };
        if msg.eq_ignore_ascii_case("exit") { break; }

        let ad  = match read_line_prompt("Associated Data (AD, in Ascii format)> ") { Ok(s) => s, Err(_) => continue };
        if ad.eq_ignore_ascii_case("exit") { break; }

        // (2) Encrypt with a fresh random 96-bit nonce per message
        let mut nonce: Nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let ct: Vec<u8> = match AEADdemo::encrypt(&key, &nonce, msg.as_bytes(), ad.as_bytes()) {
            Ok(c) => c,
            Err(e) => { eprintln!("Encrypt error: {e}"); continue; }
        };

        // Split ciphertext and tag
        let split_at = ct.len().saturating_sub(16);
        let (ciphertext, tag) = ct.split_at(split_at);

        use base64::{engine::general_purpose, Engine as _};
        let b64 = |d: &[u8]| general_purpose::STANDARD.encode(d);

        println!("\nNonce (Base64): {}", b64(&nonce));
        println!("Ciphertext (Base64): {}", b64(ciphertext));
        println!("Tag (Base64): {}", b64(tag));
        println!("Ciphertext+Tag length: {} bytes", ct.len());

        // (3) Decrypt: show success
        match AEADdemo::decrypt(&key, &nonce, &ct, ad.as_bytes()) {
            Ok(pt) => println!("Decrypt OK: '{}'", String::from_utf8_lossy(&pt)),
            Err(_) => println!("Decrypt failed (unexpected)"),
        }

        // (4) Modify ciphertext → decrypt must fail
        let mut ct_tampered = ct.clone();
        if !ct_tampered.is_empty() {
            ct_tampered[0] ^= 0x01;
        }
        let fail1 = AEADdemo::decrypt(&key, &nonce, &ct_tampered, ad.as_bytes()).is_err();
        println!("Tamper ciphertext → decrypt {}", if fail1 { "Fail" } else { "If this happen, then email runzhi.zeng@uni-kassel.de immediately" });

        // (5) Modify AD → decrypt must fail
        let ad2 = format!("{}*", ad);
        let fail2 = AEADdemo::decrypt(&key, &nonce, &ct, ad2.as_bytes()).is_err();
        println!("Modify AD → decrypt {}", if fail2 { "Fail" } else { "If this happen, then email runzhi.zeng@uni-kassel.de immediately" });
    }
    println!("Exit.");
}