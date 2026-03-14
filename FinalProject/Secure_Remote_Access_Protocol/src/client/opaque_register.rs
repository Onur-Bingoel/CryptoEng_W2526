use crate::client::alice::encrypt;
use crate::crypto::participant::{Message, User};
use aes_gcm::aead::OsRng;
use rand_core::RngCore;
use std::net::TcpStream;

pub(crate) fn register(
    k3_c: [u8; 32],
    mut stream: &mut TcpStream,
    aead_nonce: &mut [u8; 12],
    ad: &&[u8; 13],
    username: &str,
    pw: &str,
) -> bool {
    {
        let username = username.as_bytes();
        let pw = pw.as_bytes();

        // Send username and password to Google
        println!("Alice: Sending username and password to Google");
        let mut msg = Vec::new();
        msg.extend_from_slice(b"Register;");
        msg.extend_from_slice(username);
        msg.extend_from_slice(b";");
        msg.extend_from_slice(pw);
        OsRng.fill_bytes(aead_nonce);
        let cypher_text = match encrypt(&k3_c, &aead_nonce, &ad, msg) {
            Ok(value) => value,
            Err(value) => return value,
        };
        let msg = Message::AeadCiphertext {
            nonce: *aead_nonce,
            aead_payload: cypher_text,
        };
        User::send_bytes(&mut stream, &msg);
    };
    false
}