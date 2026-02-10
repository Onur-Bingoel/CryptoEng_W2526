// This is a simple Rust program that hashes a password using SHA3-256
// and then encodes the resulting hash in Base64.  
// The target hashed password that you need to hack is:
use sha3::{Digest, Sha3_256};

fn main() {

    let password = "test";

    let mut hasher = Sha3_256::new();
    hasher.update(password.as_bytes());
    let digest = hasher.finalize();

    let b64 = base64::encode(digest);
    println!("{}", b64);

    // Then you need to find a pw from the dictionary that base64(SHA3-256(pw)) = target_digest
    let target = "8yQ28QbbPQYfvpta2FBSgsZTGZlFdVYMhn7ePNbaKV8="; // The target hashed password in Base64
    let target_digest = base64::decode(target).unwrap(); // Decode the target from Base64
}
