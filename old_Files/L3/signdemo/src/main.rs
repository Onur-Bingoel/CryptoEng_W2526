mod crypto;
mod io;

use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use crypto::signdemo::{keygen, sign, verify};

fn b64(x: &[u8]) -> String {
    general_purpose::STANDARD.encode(x)
}

fn main() -> Result<()> {
    println!("Ed25519 Digital Signature Demo (type 'exit' to quit)\n");

    // 1) Generate a fresh keypair (for real apps, load from disk/HSM)
    let keypair = keygen();
    let sk_bytes = keypair.sk.to_bytes();        // [u8; 32]
    let pk_bytes = keypair.pk.to_bytes();        // [u8; 32]
    println!("Public Key (Base64): {}\n", b64(&pk_bytes));
    println!("Secret Key (Base64): {}\n", b64(&sk_bytes));


    // 2) Loop: read a message, sign, and then verify
    loop {
        let msg = io::readline::read_line_prompt("New message to sign> ")?;
        if msg.eq_ignore_ascii_case("exit") { break; }

        // Sign
        let sig = sign(&keypair.sk, msg.as_bytes());        // A ed25519_dalek::Signature
        let sig_bytes: [u8; 64] = sig.to_bytes();
        println!("Signature (Base64): {}", b64(&sig_bytes));

        // Verify the same message
        let ok = verify(&keypair.pk, msg.as_bytes(), &sig);
        println!("Verify (same message): {ok}");

        // Verify a message from input
        let msg_verify = io::readline::read_line_prompt("Message to verify> ")?;
        let ok = verify(&keypair.pk, msg_verify.as_bytes(), &sig);
        println!("Verify (your message): {ok}\n");
    }

    println!("Exit.");
    Ok(())
}
