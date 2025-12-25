mod crypto;
mod io;
mod encode;

use anyhow::Result;
use crypto::{dhke, hkdf, aead};
use rand::{rngs::OsRng, RngCore};
use encode::encode_b64::b64;
use io::readline::read_line_prompt;

fn main() -> Result<()> {
    println!("DHKE + HKDF + AEAD demo");
    println!(" - DH: X25519 (ephemeral/ephemeral in one process)");
    println!(" - KDF: HKDF-SHA3-256");
    println!(" - AEAD: AES-256-GCM");
    println!("Type 'exit' to quit.\n");

    // DHKE
    let alice = dhke::DHkeypair::keygen();
    let bob   = dhke::DHkeypair::keygen();
    println!("Alice's pk (Base64): {}", b64(&alice.pk.to_bytes()));
    println!("Bob's pk (Base64): {}", b64(&bob.pk.to_bytes()));
    let ss_alice = dhke::shared_secret(alice.sk, &bob.pk);
    let ss_bob   = dhke::shared_secret(bob.sk, &alice.pk);
    println!("Shared secret (Base64): {}", b64(&ss_alice));

    // HKDF (derive AES-256 key from the shared secret)
    let salt = None;
    let info = b"DHKE+HKDF+AESgcm";      // context string
    let key: aead::Key = hkdf::derive_aes256gcm_key(&ss_alice, salt, info);
    println!("Derived key (Base64):    {}", b64(&key));
    println!();

    // AEAD encrypt/decrypt demo
    loop {
        let ad = read_line_prompt("Associated Data (could be empty)> ")?;    // not encrypted, authenticated
        if ad.eq_ignore_ascii_case("exit") { break; }

        let msg = read_line_prompt("Plaintext to be encrypt> ")?;
        if msg.eq_ignore_ascii_case("exit") { break; }

        // fresh random 96-bit nonce per message
        let mut nonce: aead::Nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        // encrypt
        let ct = match aead::encrypt(&key, &nonce, msg.as_bytes(), ad.as_bytes()) {
            Ok(c) => c,
            Err(e) => { eprintln!("Encrypt error: {e}"); continue; }
        };

        println!("\nNonce (Base64):          {}", b64(&nonce));
        println!("Ciphertext+Tag (Base64): {}", b64(&ct));

        // decrypt to show it works
        match aead::decrypt(&key, &nonce, &ct, ad.as_bytes()) {
            Ok(pt) => println!("Decrypt OK → '{}'\n", String::from_utf8_lossy(&pt)),
            Err(_) => println!("Should not happen?\n"),
        }
    }
    Ok(())
}
