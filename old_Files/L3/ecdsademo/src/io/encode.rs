use base64::{engine::general_purpose, Engine as _};

use base64::DecodeError;

pub fn b64(x: &[u8]) -> String { general_purpose::STANDARD.encode(x) }

pub fn from_b64(s: &str) -> Result<Vec<u8>, DecodeError> {
    general_purpose::STANDARD.decode(s)
}