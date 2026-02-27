use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// Type HKDF-SHA256
pub type Hkdfsha256 = Hkdf<Sha256>;
const KEY_LEN: usize = 32;

/// Extract: returns (PRK bytes, HKDF object primed with PRK)
/// - `salt`: None uses all-zero salt per RFC 5869.
/// - return (prk, hk). The hk (equiped with prf) can be used to expand
pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> (hmac::digest::Output<Sha256>, Hkdfsha256) {
    Hkdf::<Sha256>::extract(salt, ikm)
}

/// Expand into a fixed-size array (nice for keys/IVs).
pub fn expand<const N: usize>(hk: &Hkdfsha256, info: &[u8]) -> Result<[u8; N], hkdf::InvalidLength> {
    let mut out = [0u8; N];
    hk.expand(info, &mut out)?;
    Ok(out)
}


pub fn derive_hs(shared_key: &[u8]) -> (hmac::digest::Output<Sha256>, Hkdfsha256) {
    let zero = [0u8; KEY_LEN];
    let (_es_prk, es_hk) = extract(Some(&zero), &zero);
    let d_es = expand::<KEY_LEN>(&es_hk, &Sha256::digest(b"DerivedES")).unwrap();
    let (hs_prk, hs_hk) = extract(Some(&d_es), Sha256::digest(shared_key).as_slice());
    (hs_prk, hs_hk)
}

pub fn key_schedule_1(shared_key: &[u8]) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let (_, hs_hk) = derive_hs(shared_key);
    let k_c = expand::<KEY_LEN>(&hs_hk, b"ClientKE").unwrap();
    let k_s = expand::<KEY_LEN>(&hs_hk, b"ServerKE").unwrap();
    (k_c, k_s)
}

pub fn key_schedule_2(
    nonce_c: &[u8],
    pk_c: &[u8],
    nonce_s: &[u8],
    pk_s: &[u8],
    shared_key: &[u8],
) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let (_, hs_hk) = derive_hs(shared_key);

    let mut buf = Vec::new();
    buf.extend_from_slice(nonce_c);
    buf.extend_from_slice(pk_c);
    buf.extend_from_slice(nonce_s);
    buf.extend_from_slice(pk_s);

    let mut client_buf = buf.clone();
    client_buf.extend_from_slice(b"ClientKC");
    let client_kc = Sha256::digest(&client_buf);

    let mut server_buf = buf;
    server_buf.extend_from_slice(b"ServerKC");
    let server_kc = Sha256::digest(&server_buf);

    let k_c = expand::<KEY_LEN>(&hs_hk, &client_kc).unwrap();
    let k_s = expand::<KEY_LEN>(&hs_hk, &server_kc).unwrap();
    (k_c, k_s)
}

pub fn key_schedule_3(
    nonce_c: &[u8],
    pk_c: &[u8],
    nonce_s: &[u8],
    pk_s: &[u8],
    shared_key: &[u8],
    sign: &[u8],
    cert_pk_s: &[u8],
    mac_s: &[u8],
) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let (_, hs_hk) = derive_hs(shared_key);
    let d_hs = expand::<KEY_LEN>(&hs_hk, &Sha256::digest(b"DerivedHS")).unwrap();
    let zero = [0u8; KEY_LEN];
    let (_, ms_hk) = extract(Some(&d_hs), &zero);

    let mut buf = Vec::new();
    buf.extend_from_slice(nonce_c);
    buf.extend_from_slice(pk_c);
    buf.extend_from_slice(nonce_s);
    buf.extend_from_slice(pk_s);
    buf.extend_from_slice(sign);
    buf.extend_from_slice(cert_pk_s);
    buf.extend_from_slice(mac_s);


    let mut client_buf = buf.clone();
    client_buf.extend_from_slice(b"ClientEncK");
    let client_skh = Sha256::digest(&client_buf);

    let mut server_buf = buf;
    server_buf.extend_from_slice(b"ServerEncK");
    let server_skh = Sha256::digest(&server_buf);

    let k_c = expand::<KEY_LEN>(&ms_hk, &client_skh).unwrap();
    let k_s = expand::<KEY_LEN>(&ms_hk, &server_skh).unwrap();
    (k_c, k_s)
}