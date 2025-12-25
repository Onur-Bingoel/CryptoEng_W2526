mod crypto;
mod io;


use base64::{engine::general_purpose, Engine as _};
use crypto::dhies_aesctr_hmac as dhies;
use crate::io::readline::read_line_prompt;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let me = dhies::DHIESKeypair::keygen();
    let pk_bytes = me.public_bytes();
    println!("Your DHIES public key (base64): {}", general_purpose::STANDARD.encode(pk_bytes));

    loop {
        println!("------------------ Encrypt step ------------------");
        let msg = read_line_prompt("Enter message (exit to break):")?;
        if msg.eq_ignore_ascii_case("exit") { break Ok(()); }
        let aad = read_line_prompt("Enter AAD (empty allowed): ")?;
        let aad_opt = if aad.is_empty() { None } else { Some(aad.as_bytes()) };

        let ct = dhies::encrypt(pk_bytes, msg.as_bytes(), aad_opt);
        let line = dhies::serialize_ciphertext(&ct);
        println!("\n Ciphertext:\n{}\n", line);

        println!("------------------ Decrypt step ------------------");
        let enc_line = read_line_prompt("Paste ciphertext line: ")?;
        match dhies::parse_ciphertext(&enc_line) {
            Ok(c2) => {
                let aad2 = read_line_prompt("Enter AAD used (empty if none): ")?;
                let aad2_opt = if aad2.is_empty() { None } else { Some(aad2.as_bytes()) };
                match dhies::decrypt(&me.sk, &c2, aad2_opt) {
                    Ok(pt) => println!("Decrypted: {}\n", String::from_utf8_lossy(&pt)),
                    Err(e) => println!("Decrypt/Auth failed: {e}\n"),
                }
            }
            Err(e) => println!("Cannot parse ciphertext: {e}\n"),
        }
    }
}