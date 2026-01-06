use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, Payload, Error}};
use aes_gcm::aead::generic_array::GenericArray;

/// 32-byte AES-256 key
pub type Key = [u8; 32];
/// 96-bit (12-byte) AES-GCM nonce (a.k.a. IV)
pub type Nonce = [u8; 12];

/// Encrypts `plaintext` with AES-256-GCM under `key` and `nonce`,
/// authenticating `ad` as associated data.
/// Returns: ciphertext || tag (the tag is appended by the library).
pub fn encrypt(key: &Key, nonce: &Nonce, plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    let n = GenericArray::from_slice(nonce);
    cipher.encrypt(n, Payload { msg: plaintext, aad: ad }) // returns Vec<u8>
}

/// Decrypts AES-256-GCM using `key`, `nonce`, and `ad`.
/// Returns plaintext on success; on any tampering / mismatch it returns an error.
pub fn decrypt(key: &Key, nonce: &Nonce, ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    let nonce_ga = GenericArray::from_slice(nonce);
    cipher.decrypt(nonce_ga, Payload { msg: ciphertext, aad: ad })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, rngs::OsRng};

    #[test]
    fn roundtrip_ok() {
        let mut key = [0u8; 32]; OsRng.fill_bytes(&mut key);
        let mut nonce = [0u8; 12]; OsRng.fill_bytes(&mut nonce);

        let ad = b"header";
        let pt = b"hello AEAD";

        let ct = encrypt(&key, &nonce, pt, ad).unwrap();
        let dec = decrypt(&key, &nonce, &ct, ad).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn tamper_ciphertext_fails() {
        let mut key = [0u8; 32]; OsRng.fill_bytes(&mut key);
        let mut nonce = [0u8; 12]; OsRng.fill_bytes(&mut nonce);

        let ad = b"hdr";
        let pt = b"attack at dawn";
        let mut ct = encrypt(&key, &nonce, pt, ad).unwrap();
        ct[0] ^= 0x01; // flip a bit

        assert!(decrypt(&key, &nonce, &ct, ad).is_err());
    }

    #[test]
    fn wrong_ad_fails() {
        let mut key = [0u8; 32]; OsRng.fill_bytes(&mut key);
        let mut nonce = [0u8; 12]; OsRng.fill_bytes(&mut nonce);

        let pt = b"msg";
        let ct = encrypt(&key, &nonce, pt, b"AD1").unwrap();
        assert!(decrypt(&key, &nonce, &ct, b"AD2").is_err());
    }
}
