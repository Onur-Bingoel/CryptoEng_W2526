//! DHIES over X25519 using HKDF-SHA256 and ChaCha20-Poly1305 (AEAD).
//! Nonce is derived deterministically (not transmitted).
//!
//! Suite: "DHIES:X25519-HKDF(SHA256)-CHACHA20POLY1305"

use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
type Aes256Ctr = Ctr128BE<Aes256>;
type HmacSha256 = Hmac<Sha256>;

use crate::io::encode::{b64, from_b64};

/// Suite label used for domain separation in HKDF
const SUITE_ID: &[u8] = b"DHIES:X25519_HKDF_AES256CTR_HMACSHA256";

/// X25519 static keypair for the recipient (long-term)
#[derive(Clone)]
pub struct DHIESKeypair {
    pub sk: StaticSecret,
    pub pk: PublicKey,
}

impl DHIESKeypair {
    pub fn keygen() -> Self {
        let sk = StaticSecret::random_from_rng(&mut OsRng);
        let pk = PublicKey::from(&sk);
        Self { sk, pk }
    }
    pub fn public_bytes(&self) -> [u8; 32] {
        *self.pk.as_bytes()
    }
}


/// Ciphertext for DHIES-Enc-then-Mac: (X, nonce, C, T)
#[derive(Clone, Debug)]
pub struct Ciphertext {
    pub eph_pub: [u8; 32],  // ephemeral public key, e.g., X = g^x
    pub nonce:   [u8; 16],  // AES-CTR IV/nonce
    pub ct:      Vec<u8>,   // ciphertext bytes
    pub tag:     [u8; 32],  // HMAC-SHA256 tag
}


/// HKDF-Expand with label and context.
/// out = HKDF-Expand(PRK, info = SUITE_ID || label || context)
fn hkdf_expand_labeled<const N: usize>(
    hk: &Hkdf<Sha256>,
    label: &[u8],
    context: &[u8],
) -> [u8; N] {
    let mut info = Vec::with_capacity(SUITE_ID.len() + label.len() + context.len());
    info.extend_from_slice(SUITE_ID);
    info.extend_from_slice(label);
    info.extend_from_slice(context);

    let mut out = [0u8; N];
    hk.expand(&info, &mut out).expect("HKDF-Expand length ok");
    out
}

/// Derive (K_enc, K_mac) from the shared secret `Z = g^{xy}'.
/// Salt = SUITE_ID (binds keys to this construction and separates domains)
/// PRK = HKDF-Extract(Salt, ikm = Z)
fn derive_keys(z: &[u8; 32], context: &[u8]) -> ([u8; 32], [u8; 32]) {
    // HKDF-Extract (PRK is kept inside the Hkdf object)
    let hk = Hkdf::<Sha256>::new(Some(SUITE_ID), z);

    // Two labeled expands for key separation
    let k_enc = hkdf_expand_labeled::<32>(&hk, b"|enc", context);
    let k_mac = hkdf_expand_labeled::<32>(&hk, b"|mac", context);
    (k_enc, k_mac)
}


/// Encryption
/// Returns ciphertext struct (R, nonce, C, T)
pub fn encrypt(
    recipient_pk: [u8; 32],   // recipient's public key Y
    plaintext: &[u8],         // message to encrypt
    aad_opt: Option<&[u8]>,   // optional additional authenticated data
) -> Ciphertext {
    // 1) Ephemeral keypair (secure randomness) (x, X = g^x)
    let eph_sk = EphemeralSecret::random_from_rng(&mut OsRng);
    let eph_pk = PublicKey::from(&eph_sk);  

    // 2) DH shared secret Z = Y^x
    let recip_pk = PublicKey::from(recipient_pk);
    let shared_secret = eph_sk.diffie_hellman(&recip_pk);
    let z: &[u8; 32] = shared_secret.as_bytes();

    // 3) Context binds keys to this encryption: context = X || Y
    let mut context = Vec::with_capacity(64);
    context.extend_from_slice(eph_pk.as_bytes());
    context.extend_from_slice(recip_pk.as_bytes());

    // 4) Derive two keys (labeled Expands, no manual “split”)
    //    k_enc = HKDF-Expand(PRK, "AES-key",  X||Y)  for AES-256-CTR
    //    k_mac = HKDF-Expand(PRK, "HMAC-key", X||Y)  for HMAC-SHA256
    let (k_enc, k_mac) = derive_keys(z, &context);

    // 5) Fresh random AES-CTR nonce (16 bytes) and AES-256-CTR encryption
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);

    let mut ct = plaintext.to_vec();
    // let aeskey = GenericArray::from_slice(&k_enc);
    // let iv  = GenericArray::from_slice(&nonce);
    let mut cipher = Aes256Ctr::new(&k_enc.into(), &nonce.into());
    cipher.apply_keystream(&mut ct);

    // 6) HMAC-SHA256 over (AAD || X || nonce || C)
    let aad = aad_opt.unwrap_or(b"");  // Optional AAD, empty if None
    let mut mac = HmacSha256::new_from_slice(&k_mac).expect("HMAC key length ok");
    mac.update(aad);
    mac.update(eph_pk.as_bytes());
    mac.update(&nonce);
    mac.update(&ct);
    let tag_bytes = mac.finalize().into_bytes(); // 32 bytes
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&tag_bytes);

    Ciphertext {
        eph_pub: *eph_pk.as_bytes(),
        nonce,
        ct,
        tag,
    }
}

/// Decryption
/// Returns plaintext on success; Err on auth failure.
/// Constant-time MAC verify.
pub fn decrypt(
    recipient_sk: &StaticSecret,    // The recipient's private key y
    c: &Ciphertext,
    aad_opt: Option<&[u8]>,   // optional additional authenticated data
) -> Result<Vec<u8>, &'static str> {
    // 1) Compute Z = X^y
    let eph_pk = PublicKey::from(c.eph_pub); // X = g^x, with x unknown
    let shared = recipient_sk.diffie_hellman(&eph_pk);
    let z: &[u8; 32] = shared.as_bytes();

    // 2) Context = X || Y
    let recip_pk = PublicKey::from(recipient_sk);  // Y = g^y
    let mut context = Vec::with_capacity(64);
    context.extend_from_slice(eph_pk.as_bytes());
    context.extend_from_slice(recip_pk.as_bytes());

    // 3) Derive keys
    let (k_enc, k_mac) = derive_keys(z, &context);

    // 4) Verify HMAC in constant time: AAD || X || nonce || C
    let aad = aad_opt.unwrap_or(b"");  // Optional AAD, empty if None
    let mut mac = HmacSha256::new_from_slice(&k_mac).expect("HMAC key length");
    mac.update(aad);
    mac.update(eph_pk.as_bytes());
    mac.update(&c.nonce);
    mac.update(&c.ct);
    // Either use verify_slice (constant-time)
    if mac.verify_slice(&c.tag).is_err() {
        return Err("MAC verification failed");
    }

    // 5) AES-256-CTR decrypt
    let mut pt = c.ct.clone();
    let mut cipher = Aes256Ctr::new(&k_enc.into(), &c.nonce.into());
    cipher.apply_keystream(&mut pt);

    Ok(pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correctness_with_ad() {
        let bob = DHIESKeypair::keygen();
        let msg = b"DHIES payload";
        let ad = b"associated data";

        let c = encrypt(bob.public_bytes(), msg, Some(ad));
        let p = decrypt(&bob.sk, &c, Some(ad)).expect("decrypt ok");
        assert_eq!(p, msg);
    }

    #[test]
    fn round_trip_without_ad() {
        let bob = DHIESKeypair::keygen();
        let msg = b"DHIES payload withou ad";

        let c = encrypt(bob.public_bytes(), msg, None);
        let p = decrypt(&bob.sk, &c, None).expect("decrypt ok");
        assert_eq!(p, msg);
    }

    #[test]
    fn tamper_ciphertext_detected() {
        let bob = DHIESKeypair::keygen();
        let msg = b"integrity check";
        let ad = b"random ad";

        let mut c = encrypt(bob.public_bytes(), msg, Some(ad));
        c.ct[0] ^= 0x80;                 // flip a bit
        assert!(decrypt(&bob.sk, &c, Some(ad)).is_err());
    }

    #[test]
    fn aad_mismatch_fails() {
        let bob = DHIESKeypair::keygen();

        let msg = b"AAD mismatch check";
        let good = b"correct  ad";
        let bad  = b"tampered ad";

        let c = encrypt(bob.public_bytes(), msg, Some(good));
        assert!(decrypt(&bob.sk, &c, Some(bad)).is_err());
    }
}

/// Serialize a DHIES ciphertext as: b64(eph_pub)|b64(nonce)|b64(ct)|b64(tag)
pub fn serialize_ciphertext(c: &Ciphertext) -> String {
    format!(
        "{}|{}|{}|{}",
        b64(&c.eph_pub),
        b64(&c.nonce),
        b64(&c.ct),
        b64(&c.tag)
    )
}

/// Parse a serialized ciphertext line into a Ciphertext struct.
/// Expected format: b64(eph_pub)|b64(nonce)|b64(ct)|b64(tag)
pub fn parse_ciphertext(line: &str) -> Result<Ciphertext, String> {
    let mut parts = line.split('|');

    let eph_pub = from_b64(parts.next())?;
    let nonce = from_b64(parts.next())?;
    let ct = from_b64(parts.next())?;
    let tag = from_b64(parts.next())?;

    if eph_pub.len() != 32 || nonce.len() != 16 || tag.len() != 32 {
        return Err("bad field lengths (expect eph_pub=32, nonce=16, tag=32)".into());
    }

    let mut eph_pub_arr = [0u8; 32];
    eph_pub_arr.copy_from_slice(&eph_pub);

    let mut nonce_arr = [0u8; 16];
    nonce_arr.copy_from_slice(&nonce);

    let mut tag_arr = [0u8; 32];
    tag_arr.copy_from_slice(&tag);

    Ok(Ciphertext {
        eph_pub: eph_pub_arr,
        nonce: nonce_arr,
        ct,
        tag: tag_arr,
    })
}