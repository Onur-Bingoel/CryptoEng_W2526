use crypto_bigint::rand_core::RngCore;
use ml_dsa::{signature::Signer, KeyGen, KeyPair, MlDsa65, Seed, Signature, VerifyingKey};
use rand::rngs::ThreadRng;

pub struct User {
    pub(crate) name: String,
    nonce: [u8; 8],
}

impl User {
    pub fn new(name: String, mut rng: ThreadRng) -> Self {
        let val: [u8; 8] = rng.next_u64().to_le_bytes();
        User {
            name,
            nonce: val,
        }
    }

    pub fn nonce(&self) -> [u8; 8] {
        self.nonce.clone()
    }

    pub fn send_message(&self, title: String, target_name: String, silent: bool) {
        if silent { return; }
        let self_name = self.name.clone();
        println!("--- Sending {title} from {self_name} to {target_name} ---");
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