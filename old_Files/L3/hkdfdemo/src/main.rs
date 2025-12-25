mod crypto;
mod io;

use anyhow::Result;
use crypto::hkdfdemo::{extract, expand};
use io::encode;
use io::readline::read_line_prompt;


fn main() -> Result<()> {
    let ikm: String  = read_line_prompt("IKM> ")?;
    let salt: String = read_line_prompt("Salt (empty = none)> ")?;
    let base: String = read_line_prompt("Base info> ")?;
    let salt_opt: Option<&[u8]> = if salt.is_empty() { None } else { Some(salt.as_bytes()) };

    // Extract
    let (prk, hk) = extract(salt_opt, ikm.as_bytes());
    println!("prk   (32B): {}", encode::b64(&prk));

    // Different labels for domain separation
    let label_enc: Vec<u8>   = [base.as_bytes(), b"|enc"].concat();
    let label_mac: Vec<u8>   = [base.as_bytes(), b"|mac"].concat();
    let label_nonce: Vec<u8> = [base.as_bytes(), b"|nonce12"].concat();

    // Fixed-size outputs (arrays)
    let k_enc:  [u8; 32] = expand(&hk, &label_enc).unwrap();   // Get a 32-byte output from expand
    let k_mac:  [u8; 32] = expand(&hk, &label_mac).unwrap();   // Get a 32-byte output from expand
    let nonce:  [u8; 12] = expand(&hk, &label_nonce).unwrap(); // Get a 12-byte output from expand

    println!("enc   (32B): {}", encode::b64(&k_enc));
    println!("mac   (32B): {}", encode::b64(&k_mac));
    println!("nonce (12B): {}", encode::b64(&nonce));
    Ok(())
}
