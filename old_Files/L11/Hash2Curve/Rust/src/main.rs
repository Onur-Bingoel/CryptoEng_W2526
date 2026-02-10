//! Demo: compile-time selection of (curve, hash) for hash-to-curve.

use elliptic_curve::hash2curve::ExpandMsgXmd;
use elliptic_curve::sec1::ToEncodedPoint;
use rand_core::OsRng;
use elliptic_curve::Field;

use sha2::{Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_384, Sha3_512};

use hash2curve_wrapper::hash2curve_demo;

fn print_point(label: &str, bytes: &[u8]) {
    println!("{:<28} {}", label, hex::encode(bytes));
}

fn showcase() {
    let msg = b"some password";

    // --- k256 (secp256k1) ---
    let p = hash2curve_demo::<k256::Secp256k1, ExpandMsgXmd<Sha256>>(msg)
        .expect("k256 + SHA-256 failed");
    print_point("k256 + XMD(SHA-256)", p.to_affine().to_encoded_point(true).as_bytes());

    let p = hash2curve_demo::<k256::Secp256k1, ExpandMsgXmd<Sha3_256>>(msg)
        .expect("k256 + SHA3-256 failed");
    print_point("k256 + XMD(SHA3-256)", p.to_affine().to_encoded_point(true).as_bytes());

    // --- p256 (NIST P-256) ---
    let p = hash2curve_demo::<p256::NistP256, ExpandMsgXmd<Sha256>>(msg)
        .expect("p256 + SHA-256 failed");
    print_point("p256 + XMD(SHA-256)", p.to_affine().to_encoded_point(true).as_bytes());

    let p = hash2curve_demo::<p256::NistP256, ExpandMsgXmd<Sha3_256>>(msg)
        .expect("p256 + SHA3-256 failed");
    print_point("p256 + XMD(SHA3-256)", p.to_affine().to_encoded_point(true).as_bytes());

    // --- p384 (NIST P-384) ---
    let p = hash2curve_demo::<p384::NistP384, ExpandMsgXmd<Sha384>>(msg)
        .expect("p384 + SHA-384 failed");
    print_point("p384 + XMD(SHA-384)", p.to_affine().to_encoded_point(true).as_bytes());

    let p = hash2curve_demo::<p384::NistP384, ExpandMsgXmd<Sha3_384>>(msg)
        .expect("p384 + SHA3-384 failed");
    print_point("p384 + XMD(SHA3-384)", p.to_affine().to_encoded_point(true).as_bytes());

    // --- p521 (NIST P-521) ---
    let p = hash2curve_demo::<p521::NistP521, ExpandMsgXmd<Sha512>>(msg)
        .expect("p521 + SHA-512 failed");
    print_point("p521 + XMD(SHA-512)", p.to_affine().to_encoded_point(true).as_bytes());

    let p = hash2curve_demo::<p521::NistP521, ExpandMsgXmd<Sha3_512>>(msg)
        .expect("p521 + SHA3-512 failed");
    print_point("p521 + XMD(SHA3-512)", p.to_affine().to_encoded_point(true).as_bytes());
}

fn main() {
    // Print demo points for various (curve, hash) combinations.
    showcase();

    // --- Example: Compute h(pw)^x ---
    // Use k256 and XMD(SHA3-256) for this example.

    // 1) Password input (bytes)
    let pw: &[u8] = b"a random password";

    // 2) Hash-to-curve: H(pw, dst) in k256 using XMD(SHA3-256) with fixed DST
    let h_pw: k256::ProjectivePoint =
        hash2curve_demo::<k256::Secp256k1, ExpandMsgXmd<Sha3_256>>(pw)
            .expect("hash2curve_demo (k256 + SHA3-256) failed");

    // 3) Sample secret exponent x (scalar)
    let x = k256::Scalar::random(&mut OsRng);

    // 4) Compute H(pw)^x (i.e., scalar multiplication x * H(pw))
    let hx: k256::ProjectivePoint = h_pw * x;

    // 5) Print (compressed SEC1 encoding, hex)
    println!();
    println!("pw       = {}", String::from_utf8_lossy(pw));
    println!(
        "H(pw)    = {}",
        hex::encode(h_pw.to_affine().to_encoded_point(true).as_bytes())
    );
    println!(
        "H(pw)^x  = {}",
        hex::encode(hx.to_affine().to_encoded_point(true).as_bytes())
    );

    // Print x for debugging; remove in real protocols because it is a secret exponent.
    println!("x        = {}", hex::encode(&x.to_bytes()));
}
