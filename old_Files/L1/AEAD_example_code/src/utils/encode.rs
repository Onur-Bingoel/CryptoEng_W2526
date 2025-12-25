use base64::{engine::general_purpose, Engine as _};


/// Decode Base64, accepting both padded / unpadded / URL-safe variants.
pub fn decode_b64_flex(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if let Ok(b) = general_purpose::STANDARD.decode(&cleaned) { return Ok(b); }
    if let Ok(b) = general_purpose::STANDARD_NO_PAD.decode(&cleaned) { return Ok(b); }
    if let Ok(b) = general_purpose::URL_SAFE.decode(&cleaned) { return Ok(b); }
    general_purpose::URL_SAFE_NO_PAD.decode(&cleaned)
}