use hkdf::Hkdf;
use sha2::{Digest, Sha256};

const KEY_LEN: usize = 32;

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

/// SHA-256-Digest als 32-Byte-Array
pub fn sha256_digest(data: &[u8]) -> [u8; KEY_LEN] {
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&Sha256::digest(data));
    out
}

/// Entspricht derive_hs aus dem Python-Code
pub fn derive_hs(shared_key: &[u8]) -> Result<Hkdfsha256, hkdf::InvalidLength> {
    let zero = [0u8; KEY_LEN];
    let (_, es) = extract(Some(&zero), &zero);
    let d_es = expand::<KEY_LEN>(&es, &sha256_digest(b"DerivedES"))?;
    let (_, hs) = extract(Some(&d_es), &sha256_digest(shared_key));
    Ok(hs)
}

/// Entspricht key_schedule_1
pub fn key_schedule_1(shared_key: &[u8]) -> Result<([u8; KEY_LEN], [u8; KEY_LEN]), hkdf::InvalidLength> {
    let hs = derive_hs(shared_key)?;
    let k_c = expand::<KEY_LEN>(&hs, &sha256_digest(b"ClientKE"))?;
    let k_s = expand::<KEY_LEN>(&hs, &sha256_digest(b"ServerKE"))?;
    Ok((k_c, k_s))
}

/// Entspricht key_schedule_2
pub fn key_schedule_2(
    nonce_c: &[u8],
    pk_c: &[u8],
    nonce_s: &[u8],
    pk_s: &[u8],
    shared_key: &[u8],
) -> Result<([u8; KEY_LEN], [u8; KEY_LEN]), hkdf::InvalidLength> {
    let hs = derive_hs(shared_key)?;
    let mut client_info = Vec::new();
    client_info.extend_from_slice(nonce_c);
    client_info.extend_from_slice(pk_c);
    client_info.extend_from_slice(nonce_s);
    client_info.extend_from_slice(pk_s);
    client_info.extend_from_slice(b"ClientKC");

    let mut server_info = Vec::new();
    server_info.extend_from_slice(nonce_c);
    server_info.extend_from_slice(pk_c);
    server_info.extend_from_slice(nonce_s);
    server_info.extend_from_slice(pk_s);
    server_info.extend_from_slice(b"ServerKC");

    let k_c = expand::<KEY_LEN>(&hs, &sha256_digest(&client_info))?;
    let k_s = expand::<KEY_LEN>(&hs, &sha256_digest(&server_info))?;
    Ok((k_c, k_s))
}

/// Entspricht key_schedule_3
pub fn key_schedule_3(
    nonce_c: &[u8],
    pk_c: &[u8],
    nonce_s: &[u8],
    pk_s: &[u8],
    shared_key: &[u8],
    sign: &[u8],
    cert_pk_s: &[u8],
    mac_s: &[u8],
) -> Result<([u8; KEY_LEN], [u8; KEY_LEN]), hkdf::InvalidLength> {
    let hs = derive_hs(shared_key)?;
    let d_hs = expand::<KEY_LEN>(&hs, &sha256_digest(b"DerivedHS"))?;
    let (_, ms) = extract(Some(&d_hs), &[0u8; KEY_LEN]);

    let mut client_info = Vec::new();
    client_info.extend_from_slice(nonce_c);
    client_info.extend_from_slice(pk_c);
    client_info.extend_from_slice(nonce_s);
    client_info.extend_from_slice(pk_s);
    client_info.extend_from_slice(sign);
    client_info.extend_from_slice(cert_pk_s);
    client_info.extend_from_slice(mac_s);
    client_info.extend_from_slice(b"ClientEncK");

    let mut server_info = Vec::new();
    server_info.extend_from_slice(nonce_c);
    server_info.extend_from_slice(pk_c);
    server_info.extend_from_slice(nonce_s);
    server_info.extend_from_slice(pk_s);
    server_info.extend_from_slice(sign);
    server_info.extend_from_slice(cert_pk_s);
    server_info.extend_from_slice(mac_s);
    server_info.extend_from_slice(b"ServerKC");

    let k_c = expand::<KEY_LEN>(&ms, &sha256_digest(&client_info))?;
    let k_s = expand::<KEY_LEN>(&ms, &sha256_digest(&server_info))?;
    Ok((k_c, k_s))
}