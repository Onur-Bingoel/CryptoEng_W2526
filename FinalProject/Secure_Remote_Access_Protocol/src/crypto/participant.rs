use ml_dsa::{signature::Signer, KeyGen, KeyPair, MlDsa65, Seed, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use elliptic_curve::{ProjectivePoint, Scalar};

#[derive(Serialize, Deserialize)]
pub enum Message {
    PqtlsClientHello {
        nonce_c: Vec<u8>,
        ek: Vec<u8>,
    },
    PqtlsServerHello {
        nonce_s: Vec<u8>,
        ct: Vec<u8>,
        verifying_key: Vec<u8>,
    },
    AeadCiphertext {
        aead_payload: Vec<u8>,
    },
    SimplePayload {
        payload: Vec<u8>,
    },
}

pub struct DatabaseContent {
    pub salt: Scalar<k256::Secp256k1>,
    pub lpk_c: ProjectivePoint<k256::Secp256k1>,
    pub lpk_s: ProjectivePoint<k256::Secp256k1>,
    pub lsk_s: Scalar<k256::Secp256k1>,
    pub enc_client_keys: Vec<u8>
}

pub struct User {
    pub(crate) name: String,
}

impl User {

    pub fn new(name: String) -> Self {
        User {
            name,
        }
    }

    pub fn send_bytes(stream: &mut TcpStream, msg: &Message) {
        let data = bincode::serialize(msg).unwrap();
        let len = (data.len() as u32).to_be_bytes();

        stream.write_all(&len).unwrap();
        stream.write_all(&data).unwrap();
    }

    pub fn recv_bytes(stream: &mut TcpStream) -> Message {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).unwrap();
        let len = u32::from_be_bytes(len_buf);

        let mut buf = vec![0u8; len as usize];
        stream.read_exact(&mut buf).unwrap();

        bincode::deserialize(&buf).unwrap()
    }
}


#[derive(Clone)]
pub struct CA {
    key_pair: Arc<KeyPair<MlDsa65>>,
}

impl CA {
    pub fn new() -> Self {
        let kp = MlDsa65::from_seed(&Seed::default());
        Self { key_pair: Arc::from(kp) }
    }

    pub fn verifying_key(&self) -> &VerifyingKey<MlDsa65> {
        self.key_pair.verifying_key()
    }

    pub fn generate_certificate(&self, public_key: &[u8]) -> Signature<MlDsa65> {
        self.key_pair.signing_key().sign(public_key)
    }
}
