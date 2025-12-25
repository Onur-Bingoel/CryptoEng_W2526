use base64::{engine::general_purpose, Engine as _};

pub fn b64(x: &[u8]) -> String { general_purpose::STANDARD.encode(x) }

pub fn from_b64(p: Option<&str>) -> Result<Vec<u8>, String> {
    let s = p.ok_or_else(|| "missing field".to_string())?;
    general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(|_| "invalid base64".to_string())
}