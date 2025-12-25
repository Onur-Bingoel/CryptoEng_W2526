use base64::{engine::general_purpose, Engine as _};

/// Encode bytes to Base64 (STANDARD)
pub fn b64(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

/// Decode Base64 string to bytes
pub fn from_b64(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::STANDARD.decode(s)
}