use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, EphemeralSecret, SharedSecret};

/// X25519 keypair
pub struct DHkeypair {
    pub sk: EphemeralSecret,
    pub pk: PublicKey,
}

impl DHkeypair {
    pub fn keygen() -> Self {
        let sk = EphemeralSecret::random_from_rng(OsRng);
        let pk = PublicKey::from(&sk);
        Self { sk, pk }
    }
}

/// Compute shared secret as sk * pk_peer
// Once the function is called, the sk is consumed, namely, you cannot use it anymore.
pub fn shared_secret(sk: EphemeralSecret, pk_peer: &PublicKey) -> [u8; 32] {
    sk.diffie_hellman(pk_peer).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_shared_secret_matches() {
        let alice = DHkeypair::keygen(); // Alice's key pair: (x, X)
        let bob = DHkeypair::keygen();     // Bob's key pair: (y, Y)
        let ss_alice_bob = shared_secret(alice.sk, &bob.pk); // X^y
        let ss_bob_alice = shared_secret(bob.sk, &alice.pk); // Y^x
        assert_eq!(ss_alice_bob, ss_bob_alice);
        // Make sure the basic correctness of DHKE: "X^y = Y^x".
    }
}