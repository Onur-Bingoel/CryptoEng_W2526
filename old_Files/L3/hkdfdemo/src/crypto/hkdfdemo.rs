use hkdf::Hkdf;
use sha2::Sha256;

/// Type HKDF-SHA256
pub type Hkdfsha256 = Hkdf<Sha256>;

/// Extract: returns (PRK bytes, HKDF object primed with PRK)
/// - `salt`: None uses all-zero salt per RFC 5869.
/// - return (prk, hk). The hk (equiped with prf) can be used to expand 
pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> (hkdf::hmac::digest::Output<Sha256>, Hkdfsha256) {
    Hkdf::<Sha256>::extract(salt, ikm)
}

/// Expand into a fixed-size array (nice for keys/IVs).
pub fn expand<const N: usize>(hk: &Hkdfsha256, info: &[u8]) -> Result<[u8; N], hkdf::InvalidLength> {
    let mut out = [0u8; N];
    hk.expand(info, &mut out)?;
    Ok(out)
}
