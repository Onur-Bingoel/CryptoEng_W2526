use crate::graph::{Graph, Point};
use crypto_bigint::rand_core::RngCore;
use ml_dsa::{signature::{Signer}, KeyGen, KeyPair, MlDsa65, Seed, Signature, SigningKey, VerifyingKey};
use rand::rngs::ThreadRng;
use std::sync::atomic::{AtomicU64, Ordering};

static USER_COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct User {
    id: u64,
    key_pair: KeyPair<MlDsa65>,
    nonce: [u8; 8],
}

impl User {
    pub fn new(name: String, mut rng: ThreadRng, graph: &mut Graph) -> Self {
        let id = USER_COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut seed = Seed::default();
        rng.fill_bytes(seed.as_mut());
        let kp = MlDsa65::from_seed(&seed);
        graph.positions.insert(id, Point { x: (id as i32) * 100 + 300, y: 300 });
        graph.names.insert(id, name.clone());
        let val: [u8; 8] = rng.next_u64().to_le_bytes();
        User {
            id,
            key_pair: kp,
            nonce: val,
        }
    }

    pub fn id(&self) -> u64 {
        self.id.clone()
    }

    pub fn signing_key(&self) -> &SigningKey<MlDsa65> {
        self.key_pair.signing_key()
    }

    pub fn verifying_key(&self) -> &VerifyingKey<MlDsa65> {
        self.key_pair.verifying_key()
    }

    pub fn nonce(&self) -> [u8; 8] {
        self.nonce.clone()
    }

    pub fn send_message(&self, title: String, target_id: u64, graph: &mut Graph) {
        graph.add_arrow(self.id, target_id, title);
    }

}

pub struct CA {
    key_pair: KeyPair<MlDsa65>,
}

impl CA {
    pub fn new(mut rng: ThreadRng) -> Self {
        let mut seed = Seed::default();
        rng.fill_bytes(seed.as_mut());
        let kp = MlDsa65::from_seed(&seed);
        Self { key_pair: kp }
    }

    pub fn verifying_key(&self) -> &VerifyingKey<MlDsa65> {
        self.key_pair.verifying_key()
    }

    pub fn generate_certificate(&self, public_key: &[u8]) -> Signature<MlDsa65> {
        self.key_pair.signing_key().sign(public_key)
    }
}