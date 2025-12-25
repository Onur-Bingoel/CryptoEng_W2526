use base64::{engine::general_purpose, Engine as _};

pub fn b64(x: &[u8]) -> String { general_purpose::STANDARD.encode(x) }