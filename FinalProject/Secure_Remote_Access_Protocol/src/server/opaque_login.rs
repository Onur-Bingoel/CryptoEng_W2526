use crate::crypto;
use crate::crypto::hmac::{compute_hmac, verify_hmac};
use crate::crypto::participant::{DatabaseContent, Message, User};
use crate::server::double_ratchet::double_ratchet_iteration;
use crate::server::google::{decrypt, encrypt, println, reconstruct_aead_message};
use aes_gcm::aead::OsRng;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::Field;
use image::EncodableLayout;
use k256::{ProjectivePoint, Scalar};
use rand_core::RngCore;
use std::collections::HashMap;
use std::net::TcpStream;

pub(crate) fn login(
    k3_c: [u8; 32],
    k3_s: [u8; 32],
    mut stream: &mut TcpStream,
    aead_nonce: &mut [u8; 12],
    ad: &&[u8; 13],
    database: &mut HashMap<Vec<u8>, DatabaseContent>,
    g: ProjectivePoint,
    username: &[u8],
    content: &[u8]
) -> bool {
    // ----------- OPRF stage -----------
    println("Google: OPRF stage");

    let h_pw_a = ProjectivePoint::from_bytes(content.into()).unwrap();

    // Load saved data from database
    println(&*format!("Google: Loading saved data for user: {}", String::from_utf8_lossy(username)));
    let saved_data = match database.get(username) {
        Some(data) => data,
        None => {
            eprintln!("Google: Username not found");
            return true;
        }
    };

    // Send AEAD(k3_s, {{h_pw^as, enc_client_keys}}) message from Google to Alice
    println("Google: Sending AEAD(k3_s, {{h_pw^as, enc_client_keys}}) message to Alice");
    let mut msg = Vec::new();
    msg.extend_from_slice((h_pw_a * saved_data.salt).to_bytes().as_bytes());
    msg.extend_from_slice(saved_data.enc_client_keys.as_slice());
    msg.extend_from_slice(saved_data.aead_nonce.as_bytes());
    OsRng.fill_bytes(aead_nonce);
    let cypher_text = match encrypt(&k3_s, &aead_nonce, &ad, msg) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let msg = Message::AeadCiphertext {
        nonce: *aead_nonce,
        aead_payload: cypher_text,
    };
    User::send_bytes(&mut stream, &msg);

    // Parse enc_client_keys
    let lsk_s: Scalar = saved_data.lsk_s;
    let lpk_c: ProjectivePoint = saved_data.lpk_c;
    let _lpk_s: ProjectivePoint = saved_data.lpk_s;

    // ----------- AKE stage: 3DH -----------
    println("Google: AKE stage");

    let y = Scalar::random(&mut OsRng);

    // Receive ephemeral_pk key from Alice
    println("Google: Waiting for ephemeral_pk from Alice");
    let msg = User::recv_bytes(&mut stream);
    let (nonce, aead_payload) = match reconstruct_aead_message(msg) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let decrypted_msg = match decrypt(&k3_c, &ad, &nonce, &aead_payload) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let large_x: ProjectivePoint = ProjectivePoint::from_bytes(decrypted_msg.as_slice().try_into().unwrap()).unwrap();

    // Send ephemeral_pk key to Alice
    println("Google: Sending ephemeral_pk key to Alice");
    let mut msg = Vec::new();
    msg.extend_from_slice((g * y).to_bytes().as_bytes());
    OsRng.fill_bytes(aead_nonce);
    let cypher_text = match encrypt(&k3_s, &aead_nonce, &ad, msg) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let msg = Message::AeadCiphertext {
        nonce: *aead_nonce,
        aead_payload: cypher_text
    };
    User::send_bytes(&mut stream, &msg);

    // 3DH-KServer (𝑏, 𝑦, 𝐴, 𝑋)
    println("Google: Calculating SK");
    let mut key_input = Vec::new();
    key_input.extend_from_slice((large_x * lsk_s).to_bytes().as_bytes());
    key_input.extend_from_slice((large_x * y).to_bytes().as_bytes());
    key_input.extend_from_slice((lpk_c * y).to_bytes().as_bytes());
    let (sk, _) = crypto::key_schedule::extract(None, key_input.as_bytes());

    // ----------- Key Confirmation -----------
    println("Google: Key Confirmation stage");

    // Calculate mac_s
    println("Google: Calculating mac_s");
    let (_, hk) = crypto::key_schedule::extract(None, sk.as_bytes());
    let combined_key = crypto::key_schedule::expand::<64>(&hk, b"Key Confirmation").unwrap();
    let (kc, ks) = combined_key.split_at(32);

    let mac_s = compute_hmac(ks.as_bytes(), b"Server KC");
    let expected_mac_c = compute_hmac(kc.as_bytes(), b"Client KC");

    // Receive mac_c from Alice
    println("Google: Waiting for mac_c from Alice");
    let msg = User::recv_bytes(&mut stream);
    let (nonce, aead_payload) = match reconstruct_aead_message(msg) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let mac_c = match decrypt(&k3_c, &ad, &nonce, &aead_payload) {
        Ok(value) => value,
        Err(value) => return value,
    };

    // Send mac_s to Alice
    println("Google: Sending mac_s to Alice");
    OsRng.fill_bytes(aead_nonce);
    let cypher_text = match encrypt(&k3_s, &aead_nonce, &ad, mac_s) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let msg = Message::AeadCiphertext {
        nonce: *aead_nonce,
        aead_payload: cypher_text
    };
    User::send_bytes(&mut stream, &msg);

    // Verify mac_c
    println("Google: Verifying mac_c");
    assert!(verify_hmac(
        kc.as_bytes(),
        b"Client KC",
        mac_c.as_bytes()
    ));
    assert_eq!(mac_c.as_bytes(), expected_mac_c.as_bytes());
    println("Google: Valid MACs received.");

    // End of login -----------------------------------------------------------------------------------------------------------
    // Start communication -----------------------------------------------------------------------------------------------------------

    // ----------- Double Ratchet -----------
    println("Google: Double Ratchet stage");

    let mut rk_i = sk;
    let mut _large_x_i = large_x;
    let mut y_i = y;

    #[cfg(not(test))]
    loop {
        let (large_x_plus_one, y_i_plus_1, rk_i_plus_2, _) = match double_ratchet_iteration(&mut stream, aead_nonce, &ad, g, rk_i, y_i) {
            Ok(value) => value,
            Err(value) => return value,
        };

        rk_i = rk_i_plus_2.into();
        _large_x_i = large_x_plus_one;
        y_i = y_i_plus_1;
    }

    #[cfg(test)]
    {
        return false;
    }
}