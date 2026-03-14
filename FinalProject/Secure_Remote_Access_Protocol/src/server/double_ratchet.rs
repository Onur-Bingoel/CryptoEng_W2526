use crate::crypto::key_schedule::{kdf_ck, kdf_rk};
use crate::crypto::participant::{Message, User};
use crate::server::google::{decrypt, encrypt, println, reconstruct_aead_message};
use aes_gcm::aead::OsRng;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::Field;
use hmac::digest::Output;
use image::EncodableLayout;
use k256::{ProjectivePoint, Scalar};
use rand_core::RngCore;
use sha2::Sha256;
use std::net::TcpStream;

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
    let (nonce, aead_payload) = match reconstruct_aead_message(msg) {
        Ok(value) => value,
        Err(value) => return Err(value),
    };
    let decrypted_msg = match decrypt(&k3_c, &ad, &nonce, &aead_payload) {
        Ok(value) => value,
        Err(value) => return Err(value),
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

    let message_from_user = match decrypt(&mk_1.try_into().unwrap(), &ad, &nonce.try_into().unwrap(), &Vec::from(c1)) {
        Ok(value) => value,
        Err(value) => return Err(value),
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
    let c1: Vec<u8> = match encrypt(&mk_1.try_into().unwrap(), &aead_nonce, &ad, Vec::from(message_from_server.as_bytes())) {
        Ok(value) => value,
        Err(value) => return Err(value),
    };

    // Send large_y_i_plus_one and c1 to Alice
    println("Google: Sending Y_i+1 and c1 to Alice");
    let mut msg = Vec::new();
    msg.extend_from_slice(aead_nonce.as_bytes());
    msg.extend_from_slice((g * y_i_plus_1).to_bytes().as_bytes());
    msg.extend_from_slice(c1.as_bytes());
    OsRng.fill_bytes(aead_nonce);
    let cypher_text = match encrypt(&k3_s, &aead_nonce, &ad, msg) {
        Ok(value) => value,
        Err(value) => return Err(value),
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