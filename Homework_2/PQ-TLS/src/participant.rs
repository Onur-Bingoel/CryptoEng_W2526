use crate::ecdsa::{sign, Keypair};
use crate::graph::{Graph, Point};
use crypto_bigint::rand_core::RngCore;
use k256::{AffinePoint, Scalar};
use ml_kem::kem::EncapsulationKey;
use ml_kem::MlKem768Params;
use rand::rngs::ThreadRng;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

static USER_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug)]
pub enum ContentValue {
    PublicKey(AffinePoint),
    Nonce([u8; 8]),
    EncapsulationKey(EncapsulationKey<MlKem768Params>),
}

#[derive(Clone)]
pub struct User {
    id: u64,
    name: String,
    public_key: AffinePoint,
    secret_key: Scalar,
    nonce: [u8; 8],
    content: HashMap<String, ContentValue>,
}

impl User {
    pub fn new(name: String, mut rng: ThreadRng, graph: &mut Graph) -> Self {
        let id = USER_COUNTER.fetch_add(1, Ordering::SeqCst);
        let kp = Keypair::generate();
        graph.positions.insert(id, Point { x: (id as i32) * 100 + 300, y: 300 });
        graph.names.insert(id, name.clone());
        let val: [u8; 8] = rng.next_u64().to_le_bytes();
        User {
            id,
            name,
            public_key: kp.q,
            secret_key: kp.d,
            nonce: val,
            content: HashMap::new()
        }
    }

    pub fn id(&self) -> u64 {
        self.id.clone()
    }

    pub fn secret_key(&self) -> Scalar {
        self.secret_key.clone()
    }

    pub fn public_key(&self) -> AffinePoint {
        self.public_key.clone()
    }

    pub fn nonce(&self) -> [u8; 8] {
        self.nonce.clone()
    }

    pub fn get(&self, title: &str) -> ContentValue {
        self.content.get(title).unwrap().clone()
    }

    pub fn send_message(&self, title: String, message: ContentValue, target: &mut User, graph: &mut Graph) {
        target.content.insert(title.clone(), message);
        graph.add_arrow(self.id(), target.id(), title);
    }

    pub fn send_messages(&self, titles: Vec<String>, messages: Vec<ContentValue>, target: &mut User, graph: &mut Graph) {
        if titles.len() != messages.len() {
            panic!("Number of titles and messages must be equal");
        }
        for (title, message) in titles.iter().zip(messages.iter()) {
            target.content.insert(title.clone(), message.clone());
        }
        for title in titles {
            graph.add_arrow(self.id(), target.id(), title);
        }
    }
}

#[derive(Clone)]
pub struct CA {
    public_key: AffinePoint,
    secret_key: Scalar,
}

impl CA {
    pub fn new() -> Self {
        let kp = Keypair::generate();
        CA {
            public_key: kp.q,
            secret_key: kp.d,
        }
    }

    pub fn public_key(&self) -> AffinePoint {
        self.public_key.clone()
    }

    pub fn secret_key(&self) -> Scalar {
        self.secret_key.clone()
    }

    pub fn generate_certificate(&self, public_key: &[u8]) -> Result<([u8; 32], [u8; 32]), &'static str>  {
        sign(&self.secret_key, public_key)
    }
}