use crate::crypto;
use crate::crypto::hmac::compute_hmac;
use crate::crypto::participant::{Message, User};
use aes_gcm::aead::OsRng;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::Field;
use hmac::digest::Output;
use image::EncodableLayout;
use k256::{ProjectivePoint, Scalar};
use ml_kem::EncodedSizeUser;
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::panic;
use crate::client::alice;

pub(crate) fn double_ratchet_iteration(
    mut stream: &mut &mut TcpStream,
    aead_nonce: &mut [u8; 12],
    ad: &&&[u8; 13],
    g: ProjectivePoint,
    k3_c: &[u8; 32],
    k3_s: &[u8; 32],
    mut rk_i: Output<Sha256>,
    mut large_y_i: ProjectivePoint,
    message_from_user: &str
) -> Result<(Scalar, ProjectivePoint, [u8; 32], String), bool> {
    // Calculate the new ratchet keys and encrypt the message using mk_1
    println!("Alice: Calculating new ratchet keys");
    let x_i_plus_1 = Scalar::random(&mut OsRng);
    let (rk_i_plus_1, ck_0) = kdf_rk(rk_i.as_bytes(), (large_y_i * x_i_plus_1).to_bytes().as_bytes());
    let (ck_1, mk_1) = kdf_ck(ck_0.as_bytes());
    let c1: Vec<u8> = match crypto::aead::encrypt(&mk_1.try_into().unwrap(), &aead_nonce, message_from_user.as_bytes(), &ad.to_vec()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Alice: Encrypt error: {e}");
            return Err(true);
        }
    };

    // Send large_x_plus_one and c1 to Google
    println!("Alice: Sending X_i+1 and c1 to Google");
    let mut msg = Vec::new();
    msg.extend_from_slice(aead_nonce.as_bytes());
    msg.extend_from_slice((g * x_i_plus_1).to_bytes().as_bytes());
    msg.extend_from_slice(c1.as_bytes());
    OsRng.fill_bytes(aead_nonce);
    let cypher_text: Vec<u8> = match crypto::aead::encrypt(&k3_c, &aead_nonce, msg.as_bytes(), &ad.to_vec()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Alice: Encrypt error: {e}");
            return Err(true);
        }
    };
    let msg = Message::AeadCiphertext {
        nonce: *aead_nonce,
        aead_payload: cypher_text
    };
    User::send_bytes(&mut stream, &msg);

    // Can be used for multiple messages
    let (_ck_2, _mk_2) = kdf_ck(ck_1.as_bytes());


    // Receive large_y_plus_one and c1 from Alice
    println!("Alice: Waiting for Y_i+1 and c1 from Google");
    let msg = User::recv_bytes(&mut stream);
    let (nonce, aead_payload) = match msg {
        Message::AeadCiphertext { nonce, aead_payload } => (nonce, aead_payload),
        _ => {
            match msg {
                Message::Reset {} => (),
                _ => {
                    eprintln!("Alice: Unexpected message");
                    return Err(true);
                }
            }
            alice::RECEIVED_RESET.store(true, Ordering::Relaxed);
            panic!("Alice: Unexpected message")
        },
    };
    let decrypted_msg: Vec<u8> = match crypto::aead::decrypt(&k3_s, &nonce, &aead_payload, &ad.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Alice: Decrypt error: {e}");
            return Err(true);
        }
    };
    if decrypted_msg.len() < 45 {
        eprintln!("Alice: Decrypt error: received malformed ratchet payload (len={})", decrypted_msg.len());
        return Err(true);
    }
    let (nonce_and_large_y_plus_one_as_bytes, c1) = decrypted_msg.split_at(45);
    let (nonce, large_y_plus_one_as_bytes) = nonce_and_large_y_plus_one_as_bytes.split_at(12);
    let large_y_plus_one = ProjectivePoint::from_bytes(large_y_plus_one_as_bytes.into()).unwrap();

    // Recover the chains
    println!("Alice: Recovering chains");
    let (rk_i_plus_2, ck_0) = kdf_rk(rk_i_plus_1.as_bytes(), (large_y_plus_one * x_i_plus_1).to_bytes().as_bytes());
    let (ck_1, mk_1) = kdf_ck(ck_0.as_bytes());

    let message_from_server: Vec<u8> = match crypto::aead::decrypt(&mk_1.try_into().unwrap(), &nonce.try_into().unwrap(), &c1, &ad.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Alice: Decrypt error: {e}");
            return Err(true);
        }
    };

    let message_text = String::from_utf8_lossy(&message_from_server);
    println!("Alice: Received message from Google: {}", message_text);

    // Can be used for multiple messages
    let (_ck_2, _mk_2) = kdf_ck(ck_1.as_bytes());
    Ok((x_i_plus_1, large_y_plus_one, rk_i_plus_2, format!("{}", message_text)))
}

fn kdf_ck(ck_i: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let ck_i_plus_1 = compute_hmac(ck_i.as_bytes(), b"ChainKey");
    let mk_i = compute_hmac(ck_i.as_bytes(), b"MessageKey");

    (ck_i_plus_1, mk_i)
}

fn kdf_rk(rk_i: &[u8], dh: &[u8]) -> ([u8; 32], [u8; 32]) {
    let (_, hk) = crypto::key_schedule::extract(Some(rk_i), dh);
    let rk_i_plus_1 = crypto::key_schedule::expand::<32>(&hk, b"RootKey").unwrap();
    let ck_i = crypto::key_schedule::expand::<32>(&hk, b"ChainKey").unwrap();

    (rk_i_plus_1, ck_i)
}