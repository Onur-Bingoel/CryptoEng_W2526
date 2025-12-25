//! Simple ECDSA demo using k256 (secp256k1).
//! - Keypair uses k256::Scalar for private exponent and AffinePoint for public key.
//! - Supports sign_with_nonce (caller supplies nonce k) and sign (random k).
//! - Warning: This is a teaching demo only. Do NOT use in practice.

use k256::elliptic_curve::{
    point::AffineCoordinates,
    sec1::ToEncodedPoint,
    bigint::U256,
    ops::Reduce
};
use k256::{Scalar,AffinePoint, ProjectivePoint}; 
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// A simple ECDSA keypair representation
#[derive(Clone, Debug)]
pub struct Keypair {
    /// private exponent d
    pub d: Scalar,
    /// public key Q = d * G
    pub q: AffinePoint,
}

impl Keypair {
    /// generate a fresh random keypair
    pub fn generate() -> Self {
        // generate random scalar in [1..n-1]
        let scalar = Scalar::generate_vartime(&mut OsRng);
        let pk_point = AffinePoint::from(ProjectivePoint::GENERATOR * scalar);
        Keypair { d: scalar, q: pk_point }
    }

    /// return the public key in uncompressed SEC1 bytes
    pub fn public_bytes_uncompressed(&self) -> Vec<u8> {
        self.q.to_encoded_point(false).as_bytes().to_vec()
    }

    /// return the private scalar as 32-byte big-endian
    pub fn private_bytes(&self) -> [u8; 32] {
        self.d.to_bytes().into()
    }
}

/// Compute ECDSA signature (r, s) given private scalar `d`, message `msg`,
/// and ephemeral nonce scalar `k`. All arithmetic done modulo curve order.
///
/// Returns (r_bytes[32], s_bytes[32]) on success; if r == 0 or s == 0 returns Err.
pub fn sign_with_nonce(
    d: &Scalar, 
    msg: &[u8], 
    k: &Scalar) 
    -> Result<([u8; 32], [u8; 32]), &'static str> {
    // Reject zero nonce
    if bool::from(k.is_zero()) {
        return Err("k must be non-zero");
    }
        
    // 1. e = HASH(msg) reduced to scalar
    let e_hash = Sha256::digest(msg);
    let e_bytes: &[u8] = &e_hash[..];
    let e = scalar_reduce_from_slice(e_bytes);

    // 2. R = k*G, the nonce k is from input
    
    let r_affine: AffinePoint = AffinePoint::from(ProjectivePoint::GENERATOR * k);

    // x-coordinate as field bytes (FieldBytes<Secp256k1>)
    let x = r_affine.x();
    let x_bytes: &[u8] = &x[..];
    // reduce x mod n to get the ECDSA `r` scalar
    let r = scalar_reduce_from_slice(x_bytes);

    if bool::from(r.is_zero()) {
        return Err("r == 0. Choose a different k");
    }

    // 3. s = k^{-1} * (e + r * d) mod n
    let k_inv = k.invert().unwrap();
    let rd = r * d;               // r * d (Scalar)
    let e_plus_rd = e + rd;       // Scalar addition e + rd (mod n)
    let s = k_inv * e_plus_rd;    // Scalar multiplication k^{-1} * (e + r*d)

    if bool::from(s.is_zero()) {
        return Err("s == 0. Choose a different k");
    }

    Ok((r.to_bytes().into(), s.to_bytes().into()))
}

/// Sign using a fresh random nonce k.
pub fn sign(
    d: &Scalar, 
    msg: &[u8]) 
    -> Result<([u8; 32], [u8; 32]), &'static str> {
    let k = Scalar::generate_vartime(&mut OsRng);
    sign_with_nonce(d, msg, &k)
}

/// Verify ECDSA signature (r,s) against public key Q and message `msg`.
/// Returns true if valid.
pub fn verify(
    q: &AffinePoint, 
    msg: &[u8], 
    r_bytes: &[u8; 32], 
    s_bytes: &[u8; 32]) 
    -> bool {
    // convert to scalar
    let r = scalar_reduce_from_slice(r_bytes);
    let s = scalar_reduce_from_slice(s_bytes);

    // r and s must be in [1, n-1]
    if (r.is_zero() | s.is_zero()).into() {
        return false;
    }

    // e = HASH(msg) reduced
    let e_hash = Sha256::digest(msg);
    let e_bytes: &[u8] = &e_hash[..];
    let e = scalar_reduce_from_slice(e_bytes);
    

    let s_inv = s.invert().unwrap();
    let u1 = e * s_inv; // Scalar
    let u2 = r * s_inv; // Scalar

    // compute point = u1*G + u2*Q
    let p = ProjectivePoint::GENERATOR * u1 + ProjectivePoint::from(*q) * u2;
    let p_aff = AffinePoint::from(p);
    let x = p_aff.x();
    let x_bytes: &[u8] = &x[..];
    let x_red = scalar_reduce_from_slice(&x_bytes);
    
    // signature valid if r == x_red
    x_red == r
}

// Reduce 32 bytes modulo n (works for digests, nonces, etc.)
fn scalar_reduce_from_slice(bytes: &[u8]) -> Scalar {
    Scalar::reduce(U256::from_be_slice(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::{
        Scalar
    };

    #[test]
    fn sign_verify_with_chosen_nonce() {
        let kp = Keypair::generate();
        let msg = b"ecdas demo test message";
        // teaching-only fixed nonce (INSECURE in real systems)
        let k = Scalar::from(0xDEADBEEFu32);

        let (r, s) = sign_with_nonce(&kp.d, msg, &k).expect("sign_with_nonce");
        assert!(verify(&kp.q, msg, &r, &s));
    }

    #[test]
    fn sign_verify_random_nonce() {
        let kp = Keypair::generate();
        let msg = b"random nonce signing";

        let (r, s) = sign(&kp.d, msg).expect("sign");
        assert!(verify(&kp.q, msg, &r, &s));
    }

    #[test]
    fn verify_fails_if_message_tampered() {
        let kp = Keypair::generate();
        let msg = b"original";
        let (r, s) = sign(&kp.d, msg).expect("sign");
        let msg_tamper = b"tampered";
        assert!(!verify(&kp.q, msg_tamper, &r, &s));
    }

    #[test]
    fn r_is_equal_when_nonce_reused() {
        let kp = Keypair::generate();
        let k = Scalar::from(42u32);

        let (r1, _s1) = sign_with_nonce(&kp.d, b"m1", &k).expect("s1");
        let (r2, _s2) = sign_with_nonce(&kp.d, b"m2", &k).expect("s2");

        assert_eq!(r1, r2, "reusing k produces the same r");
    }
}


#[cfg(test)]
mod cross_tests {
    use super::*;
    use k256::{
        ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey},
        Scalar,
        AffinePoint,
        PublicKey,
        elliptic_curve::sec1::ToEncodedPoint
    };

    #[test]
    fn ecdsademo_verify_vs_k256_sign() {
        // 1. Generate a keypair using k256 high-level API
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verify_key = VerifyingKey::from(&signing_key);

        // 2. Sign message using k256's sign()
        let msg = b"cross-verify test 1";
        let sig: Signature = signing_key.sign(msg);

        // 3. Extract (r, s) from k256::Signature into our Scalars
        let r: [u8; 32] = sig.r().to_bytes().into();
        let s: [u8; 32] = sig.s().to_bytes().into();

        // 4. Verify using the verify() in the ecdsademo module
        let ep = verify_key.to_encoded_point(false);                  // SEC1 uncompressed
        let pk = PublicKey::from_sec1_bytes(ep.as_bytes()).unwrap();  // parse SEC1
        let q: AffinePoint = AffinePoint::from(&pk);                  // this impl exists
        assert!(
            verify(&q, msg, &r, &s),
            "The verify() in demo should accept k256::sign() signature"
        );
    }  
    #[test]
    fn ecdsademo_verify_vs_k256_sign_repeat() {
        for i in 0..1_000 {
            ecdsademo_verify_vs_k256_sign();
        }
    }

    #[test]
    fn ecdsademo_sign_vs_k256_verify() {
        // 1. Generate random scalar as private key
        let sk = Scalar::generate_vartime(&mut rand::thread_rng());
        let q_affine = AffinePoint::from(ProjectivePoint::GENERATOR * sk);

        // 2. Sign message using our implementation
        let msg = b"our sign algorithm is compatible with k256 verify.";
        let (r, s) = sign(&sk, msg).expect("sign");

        // 3. Build k256::Signature from our (r,s)
        let sig_unnormalized = Signature::from_scalars(r, s).expect("construct Signature");
        let sig = sig_unnormalized.normalize_s().unwrap_or(sig_unnormalized); // Normalize to low-s (k256 rejects high-s)
 

        // 4. Verify using k256 verifier
        let vk = VerifyingKey::from_encoded_point(&q_affine.to_encoded_point(false)).unwrap();
        vk.verify(msg, &sig)
            .expect("k256 should verify our signature correctly");
    }

    #[test]
    fn ecdsademo_sign_vs_k256_verify_repeat() {
        for i in 0..1_000 {
            ecdsademo_sign_vs_k256_verify();
        }
    }
}