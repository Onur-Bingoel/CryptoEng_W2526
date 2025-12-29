use hmac::{Hmac, Mac};
use sha3::Sha3_256;

type HmacSha3_256 = Hmac<Sha3_256>;

/// Computes HMAC-SHA3-256 of a message under a key.
/// Returns the raw 32-byte tag.
pub fn compute_hmac(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha3_256::new_from_slice(key).unwrap();
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// Verifies a given HMAC tag (constant-time comparison).
pub fn verify_hmac(key: &[u8], message: &[u8], tag: &[u8]) -> bool {
    if tag.len() != 32 {
        return false;
    }
    let mut mac = HmacSha3_256::new_from_slice(key).unwrap();
    mac.update(message);
    mac.verify_slice(tag).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_basic_correctness() {
        let key = b"secretkey";
        let msg = b"hello";
        let tag = compute_hmac(key, msg);
        assert!(verify_hmac(key, msg, &tag));
    }

    #[test]
    fn hmac_rejects_wrong_tag() {
        let key = b"secretkey";
        let msg = b"hello";
        let mut tag = compute_hmac(key, msg);
        tag[0] ^= 0x01; // flip a bit
        assert!(!verify_hmac(key, msg, &tag));
    }

    #[test]
    fn hmac_different_message_fails() {
        let key = b"secretkey";
        let msg1 = b"hello";
        let msg2 = b"world";
        let tag = compute_hmac(key, msg1);
        assert!(!verify_hmac(key, msg2, &tag));
    }
}
