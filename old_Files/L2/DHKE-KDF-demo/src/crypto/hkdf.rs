use hkdf::Hkdf;
use sha3::Sha3_256;

/// Derive a 32-byte key for AES-256-GCM using HKDF-SHA3-256.
pub fn derive_aes256gcm_key(
    seed: &[u8],                // input key material
    salt: Option<&[u8]>,        // salt, optional(None -> zero-salt)
    context: &[u8],                // context string / transcript hash, etc.
) -> [u8; 32] {
    let hk = Hkdf::<Sha3_256>::new(salt, seed);
    let mut key = [0u8; 32];
    hk.expand(context, &mut key).expect("This key is for AES-GCM, deriving from DH shared secret");
    key
}
