use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;

/// Ed25519 keypair (secret/public)
pub struct Keypair {
    pub sk: SigningKey,
    pub pk: VerifyingKey,
}

/// Generate a Ed25519 keypair
pub fn keygen() -> Keypair {
    let sk = SigningKey::generate(&mut OsRng); // If it shows "no generate function in "SigningKey"", then run $ cargo add ed25519_dalek --features rand_core
    let pk = sk.verifying_key();
    Keypair { sk, pk }
}

/// Sign message bytes with the secret key. Returns 64-byte signature.
pub fn sign(sk: &SigningKey, msg: &[u8]) -> Signature {
    sk.sign(msg)
}

/// Verify (pk, msg, sig). Returns true if valid.
pub fn verify(pk: &VerifyingKey, msg: &[u8], sig: &Signature) -> bool {
    pk.verify(msg, sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sign_then_verify() {
        let kp = keygen();
        let msg = b"hello";
        let sig = sign(&kp.sk, msg);
        assert!(verify(&kp.pk, msg, &sig));
        assert!(!verify(&kp.pk, b"random message", &sig));
    }
}
