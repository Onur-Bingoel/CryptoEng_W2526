use crate::crypto;
use crate::crypto::hmac::compute_hmac;
use crate::crypto::participant::{Message, User};
use crate::server::google;
use aes_gcm::aead::OsRng;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::Field;
use hmac::digest::{Digest, Output};
use image::EncodableLayout;
use k256::{ProjectivePoint, Scalar};
use ml_kem::EncodedSizeUser;
use rand_core::RngCore;
use sha2::Sha256;
use std::net::TcpStream;
use std::panic;
use std::sync::atomic::Ordering;
use crate::server::google::println;

pub(crate) fn double_ratchet_iteration(
    k3_c: &[u8; 32],
    k3_s: &[u8; 32],
    mut stream: &mut &mut TcpStream,
    aead_nonce: &mut [u8; 12],
    ad: &&&[u8; 13],
    g: ProjectivePoint,
    rk_i: Output<Sha256>,
    y_i: Scalar
) -> Result<(ProjectivePoint, Scalar, [u8; 32], String), bool> {
    // Receive large_x_i_plus_one and c1 from Alice
    println("Google: Waiting for X_i+1 and c1 from Alice");
    let msg = User::recv_bytes(&mut stream);
    let (nonce, aead_payload) = match msg {
        Message::AeadCiphertext { nonce, aead_payload } => (nonce, aead_payload),
        _ => {
            match msg {
                Message::Reset {} => (),
                _ => {
                    eprintln!("Google: Unexpected message");
                    return Err(true);
                }
            }
            google::RECEIVED_RESET.store(true, Ordering::Relaxed);
            panic!("Google: Unexpected message")
        },
    };
    let decrypted_msg: Vec<u8> = match crypto::aead::decrypt(&k3_c, &nonce, &aead_payload, &ad.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Google: Decrypt error: {e}");
            return Err(true);
        }
    };
    if decrypted_msg.len() < 45 {
        eprintln!("Google: Decrypt error: received malformed ratchet payload (len={})", decrypted_msg.len());
        return Err(true);
    }
    let (nonce_and_large_x_plus_one_as_bytes, c1) = decrypted_msg.split_at(45);
    let (nonce, large_x_plus_one_as_bytes) = nonce_and_large_x_plus_one_as_bytes.split_at(12);
    let large_x_plus_one = ProjectivePoint::from_bytes(large_x_plus_one_as_bytes.into()).unwrap();

    // Recover the chains
    println("Google: Recovering chains");
    let (rk_i_plus_1, ck_0) = kdf_rk(rk_i.as_bytes(), (large_x_plus_one * y_i).to_bytes().as_bytes());
    let (ck_1, mk_1) = kdf_ck(ck_0.as_bytes());

    let message_from_user: Vec<u8> = match crypto::aead::decrypt(&mk_1.try_into().unwrap(), &nonce.try_into().unwrap(), &c1, &ad.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Google: Decrypt error: {e}");
            return Err(true);
        }
    };

    // Echo message_from_user
    let message_text = String::from_utf8_lossy(&message_from_user);
    let message_from_server = format!("Echo => {}", message_text);

    // Can be used for multiple messages
    let (_ck_2, _mk_2) = kdf_ck(ck_1.as_bytes());


    // Encrypt message_from_server with DH Ratchet and Sym Ratchet
    println("Google: Encrypting message_from_server with DH Ratchet and Sym Ratchet");
    let y_i_plus_1 = Scalar::random(&mut OsRng);
    let (rk_i_plus_2, ck_0) = kdf_rk(rk_i_plus_1.as_bytes(), (large_x_plus_one * y_i_plus_1).to_bytes().as_bytes());
    let (ck_1, mk_1) = kdf_ck(ck_0.as_bytes());
    OsRng.fill_bytes(aead_nonce);
    let c1: Vec<u8> = match crypto::aead::encrypt(&mk_1.try_into().unwrap(), &aead_nonce, message_from_server.as_bytes(), &ad.to_vec()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Google: Encrypt error: {e}");
            return Err(true);
        }
    };

    // Send large_y_i_plus_one and c1 to Alice
    println("Google: Sending Y_i+1 and c1 to Alice");
    let mut msg = Vec::new();
    msg.extend_from_slice(aead_nonce.as_bytes());
    msg.extend_from_slice((g * y_i_plus_1).to_bytes().as_bytes());
    msg.extend_from_slice(c1.as_bytes());
    OsRng.fill_bytes(aead_nonce);
    let cypher_text: Vec<u8> = match crypto::aead::encrypt(&k3_s, &aead_nonce, msg.as_bytes(), &ad.to_vec()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Google: Encrypt error: {e}");
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
    Ok((large_x_plus_one, y_i_plus_1, rk_i_plus_2, format!("{}", message_text)))
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