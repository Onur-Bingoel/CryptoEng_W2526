use hkdf::Hkdf;
use sha3::Sha3_256;

/// Derive `out_len` bytes using HKDF-SHA3-256.
/// - `seed`  → IKM (input keying material)
/// - `salt`  → optional salt (None uses RFC 5869 "zeros" salt)
/// - `info`  → context string / auxiliary data
pub fn hkdf_sha3_256(seed: &[u8], salt: Option<&[u8]>, info: &[u8], out_len: usize)
    -> Result<Vec<u8>, hkdf::InvalidLength>
{
    let hk = Hkdf::<Sha3_256>::new(salt, seed);
    let mut okm = vec![0u8; out_len];
    hk.expand(info, &mut okm)?;
    Ok(okm)
}


/// Derive a 32-byte key for AES-256-GCM.
pub fn derive_aes256gcm_key(
    seed: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
) -> Result<[u8; 32], hkdf::InvalidLength> {
    let hk = Hkdf::<Sha3_256>::new(salt, seed);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_same_inputs() {
        let seed = b"supersecret";
        let info = b"session-1";
        let k1 = derive_aes256gcm_key(seed, None, info).unwrap();
        let k2 = derive_aes256gcm_key(seed, None, info).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn different_info_gives_different_keys() {
        let seed = b"supersecret";
        let k1 = derive_aes256gcm_key(seed, None, b"A").unwrap();
        let k2 = derive_aes256gcm_key(seed, None, b"B").unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn length_generic() {
        let seed = b"x";
        let okm = hkdf_sha3_256(seed, None, b"", 48).unwrap();
        assert_eq!(okm.len(), 48);
    }
}
