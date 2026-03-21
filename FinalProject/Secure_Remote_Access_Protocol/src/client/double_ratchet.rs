use crate::client::alice::{decrypt, encrypt, RECEIVED_RESET};
use crate::crypto::key_schedule::{kdf_ck, kdf_rk};
use crate::crypto::participant::{Message, User};
use aes_gcm::aead::OsRng;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::Field;
use hmac::digest::Output;
use image::EncodableLayout;
use k256::{ProjectivePoint, Scalar};
use sha2::Sha256;
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use rand_core::RngCore;

pub(crate) fn double_ratchet_iteration(
    mut stream: &mut &mut TcpStream,
    aead_nonce: &mut [u8; 12],
    ad: &&&[u8; 13],
    g: ProjectivePoint,
    rk_i: Output<Sha256>,
    large_y_i: ProjectivePoint,
    message_from_user: &str
) -> Result<(Scalar, ProjectivePoint, [u8; 32], String), bool> {
    // Calculate the new ratchet keys and encrypt the message using mk_1
    println!("Alice: Calculating new ratchet keys");
    let x_i_plus_1 = Scalar::random(&mut OsRng);
    let (rk_i_plus_1, ck_0) = kdf_rk(rk_i.as_bytes(), (large_y_i * x_i_plus_1).to_bytes().as_bytes());
    let (ck_1, mk_1) = kdf_ck(ck_0.as_bytes());
    OsRng.fill_bytes(aead_nonce);
    let c1 = match encrypt(&mk_1.try_into().unwrap(), &aead_nonce, &ad, Vec::from(message_from_user.as_bytes())) {
        Ok(value) => value,
        Err(value) => return Err(value),
    };

    // Send large_x_plus_one and c1 to Google
    println!("Alice: Sending X_i+1 and c1 to Google");
    let msg = Message::DoubleRatchetPayload {
        nonce: *aead_nonce,
        ciphertext: c1,
        public_key: (g * x_i_plus_1).to_bytes().as_bytes().to_vec(),
    };
    User::send_bytes(&mut stream, &msg);

    // Can be used for multiple messages
    let (_ck_2, _mk_2) = kdf_ck(ck_1.as_bytes());


    // Receive large_y_plus_one and c1 from Alice
    println!("Alice: Waiting for Y_i+1 and c1 from Google");
    let msg = User::recv_bytes(&mut stream);
    let (nonce, c1, large_y_plus_one_as_bytes) = match msg {
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
    let large_y_plus_one = ProjectivePoint::from_bytes(large_y_plus_one_as_bytes.as_bytes().into()).unwrap();

    // Recover the chains
    println!("Alice: Recovering chains");
    let (rk_i_plus_2, ck_0) = kdf_rk(rk_i_plus_1.as_bytes(), (large_y_plus_one * x_i_plus_1).to_bytes().as_bytes());
    let (ck_1, mk_1) = kdf_ck(ck_0.as_bytes());

    let message_from_server = match decrypt(&mk_1.try_into().unwrap(), &ad, &nonce.try_into().unwrap(), &Vec::from(c1)) {
        Ok(value) => value,
        Err(value) => return Err(value),
    };

    let message_text = String::from_utf8_lossy(&message_from_server);
    println!("Alice: Received message from Google: {}", message_text);

    // Can be used for multiple messages
    let (_ck_2, _mk_2) = kdf_ck(ck_1.as_bytes());
    Ok((x_i_plus_1, large_y_plus_one, rk_i_plus_2, format!("{}", message_text)))
}