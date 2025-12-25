mod io;
mod crypto;

use crypto::ecdsademo::*;
use io::readline::read_line_prompt;
use k256::Scalar;
use k256::elliptic_curve::ops::Reduce;
use sha2::{Digest, Sha256};
use crypto_bigint::U256;
use crypto_bigint::subtle::ConstantTimeEq;

// helper: print the Scalar in the hex format
fn scalar_to_hex(s: &Scalar) -> String {
    use k256::elliptic_curve::ff::PrimeField;
    let fb = s.to_repr();           // Scalar to FieldBytes (GenericArray)
    let arr: [u8; 32] = fb.into();  // FileBytes to [u8; 32]
    hex::encode(arr)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("ECDSA demo (k256, secp256k1)");

    // Generate keypair
    let keypair = Keypair::generate();
    println!("\nKeypair generated.");
    // println!("Private key (hex): {:02x?}", keypair.private_bytes());
    // println!("Public key (uncompressed): {:02x?}", keypair.public_bytes_uncompressed());

    // For demo: choose a fixed nonce (insecure)
    let k = Scalar::from(0xBADDBu64);
    println!("The nonce is (hex): {}", scalar_to_hex(&k));

    // Read message
    let msg1 = read_line_prompt("\nEnter a message to sign: ")?;
    let msg1_bytes = msg1.as_bytes();


    // Sign
    let (r1_bytes, s1_bytes) = sign_with_nonce(&keypair.d, msg1_bytes, &k)?;
    println!("\nSignature:");
    println!("r = {:02x?}", r1_bytes);
    println!("s1 = {:02x?}", s1_bytes);

    // Verify
    let ok = verify(&keypair.q, msg1_bytes, &r1_bytes, &s1_bytes);
    println!("Verification result: {}", ok);

    // Sign with another message 
    // You should choose a message different from the first one, otherwise the attack will fail since both signatures will be identical
    let msg2 = read_line_prompt("\nEnter a different message to sign: ")?;
    let msg2_bytes = msg2.as_bytes();
    let (r2_bytes, s2_bytes) = sign_with_nonce(&keypair.d, msg2_bytes, &k)?;
    println!("\nSignature:");
    println!("r = {:02x?}", r2_bytes);
    println!("s2 = {:02x?}", s2_bytes);

    let r1 = Scalar::reduce(U256::from_be_slice(&r1_bytes));
    let s1 = Scalar::reduce(U256::from_be_slice(&s1_bytes));
    let r2 = Scalar::reduce(U256::from_be_slice(&r2_bytes));
    let s2 = Scalar::reduce(U256::from_be_slice(&s2_bytes));
    let z1 = Scalar::reduce(U256::from_be_slice(Sha256::digest(msg1).as_slice())); // z1 = H(msg1)
    let z2 = Scalar::reduce(U256::from_be_slice(Sha256::digest(msg2).as_slice())); // z2 = H(msg2)

    // Now, we have msg1, msg2, r, s1, and s2. Implement your attack here! 
    // You goal is to recover the private key 'd' from these values.
    // To see how we operate on Scalars, refer to the implementation of sign_with_nonce().

    Ok(())
}