use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use x509_parser::{prelude::*, pem::Pem};

#[derive(Debug, Clone)]
pub struct Cert {
    pub subject: String,
    pub issuer: String,
    pub serial_hex: String,
    pub not_before: String,
    pub not_after: String,
    pub pk_algorithm_name: String,
    pub sha256_fingerprint_hex: String,
    pub public_key_der: Vec<u8>,
}

/// Parse one DER-encoded certificate and summarize it.
pub fn parse_cert_der(der: &[u8]) -> Result<Cert> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| anyhow!("DER parse error: {e:?}"))?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let serial_hex = hex::encode(cert.raw_serial().to_vec());
    let not_before = cert.validity().not_before.to_rfc2822().unwrap_or_else(|_| "<invalid>".into());
    let not_after = cert.validity().not_after.to_rfc2822().unwrap_or_else(|_| "<invalid>".into());
    let spki = cert.public_key();
    let pk_algorithm_oid = spki.algorithm.algorithm.to_id_string();
    let pk_algorithm_name = oid_to_algorithm_name(&pk_algorithm_oid);
    let fp_hex = hex::encode(Sha256::digest(der));
    let public_key_der = spki.subject_public_key.data.to_vec();

    Ok(Cert {
        subject,
        issuer,
        serial_hex,
        not_before,
        not_after,
        pk_algorithm_name: pk_algorithm_name.to_string(),
        sha256_fingerprint_hex: fp_hex,
        public_key_der,
    })
}

/// Auto-detect PEM vs DER. For PEM, iterate all CERTIFICATE blocks.
pub fn parse_pem_or_der(data: &[u8]) -> Result<Vec<(usize, Cert)>> {
    if std::str::from_utf8(data).ok().map_or(false, |s| s.contains("-----BEGIN")) {
        let mut out = Vec::new();
        for (i, pem_result) in Pem::iter_from_buffer(data).enumerate() {
            if let Ok(pem) = pem_result {
                if pem.label == "CERTIFICATE" {
                    let info = parse_cert_der(&pem.contents)?;
                    out.push((i, info));
                }
            }
        }
        if out.is_empty() {
            return Err(anyhow!("No PEM CERTIFICATE blocks found"));
        }
        Ok(out)
    } else {
        let info = parse_cert_der(data)?;
        Ok(vec![(0, info)])
    }
}

fn oid_to_algorithm_name(oid: &str) -> &'static str {
    match oid {
        // RSA
        "1.2.840.113549.1.1.1" => "RSA Encryption",
        "1.2.840.113549.1.1.5" => "SHA1 with RSA",
        "1.2.840.113549.1.1.11" => "SHA256 with RSA",
        "1.2.840.113549.1.1.12" => "SHA384 with RSA",
        "1.2.840.113549.1.1.13" => "SHA512 with RSA",

        // ECDSA
        "1.2.840.10045.2.1" => "EC Public Key",
        "1.2.840.10045.4.3.2" => "ECDSA with SHA256",
        "1.2.840.10045.4.3.3" => "ECDSA with SHA384",
        "1.2.840.10045.4.3.4" => "ECDSA with SHA512",

        // EdDSA
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",

        // DSA
        "1.2.840.10040.4.1" => "DSA",

        // Fallback
        _ => "Unknown Algorithm",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_garbage() {
        let bad = b"not a certificate";
        assert!(parse_pem_or_der(bad).is_err());
    }
}