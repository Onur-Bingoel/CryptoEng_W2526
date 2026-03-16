use crate::crypto::key_schedule::{kdf_ck, kdf_rk};
use crate::crypto::participant::{Message, User};
use crate::server::google::{decrypt, encrypt, println, RECEIVED_RESET};
use aes_gcm::aead::OsRng;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::Field;
use hmac::digest::Output;
use image::EncodableLayout;
use k256::{ProjectivePoint, Scalar};
use rand_core::RngCore;
use sha2::Sha256;
use std::net::TcpStream;
use std::sync::atomic::Ordering;

pub(crate) fn double_ratchet_iteration(
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
    let (nonce, c1, large_x_plus_one_as_bytes) = match msg {
        Message::DoubleRatchetPayload {nonce, ciphertext, public_key} => (nonce, ciphertext, public_key),
        _ => {
            match msg {
                Message::Reset {} => (),
                _ => {
                    eprintln!("Google: Unexpected message");
                    return Err(true);
                }
            }
            RECEIVED_RESET.store(true, Ordering::Relaxed);
            eprintln!("Google: Unexpected message");
            return Err(true);
        },
    };
    let large_x_plus_one = ProjectivePoint::from_bytes(large_x_plus_one_as_bytes.as_bytes().into()).unwrap();

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
    let msg = Message::DoubleRatchetPayload {
        nonce: *aead_nonce,
        ciphertext: c1,
        public_key: (g * y_i_plus_1).to_bytes().as_bytes().to_vec(),
    };
    User::send_bytes(&mut stream, &msg);

    // Can be used for multiple messages
    let (_ck_2, _mk_2) = kdf_ck(ck_1.as_bytes());
    Ok((large_x_plus_one, y_i_plus_1, rk_i_plus_2, format!("{}", message_text)))
}