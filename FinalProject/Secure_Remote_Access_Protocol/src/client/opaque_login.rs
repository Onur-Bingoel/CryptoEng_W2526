use crate::client::alice::{decrypt, encrypt, reconstruct_aead_message};
use crate::client::double_ratchet::double_ratchet_iteration;
use crate::crypto;
use crate::crypto::hash2curve::hash2curve_demo;
use crate::crypto::hmac::{compute_hmac, verify_hmac};
use crate::crypto::participant::{Message, User, ENC_CLIENT_KEYS_LEN, MAC_LEN};
use aes_gcm::aead::OsRng;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::hash2curve::ExpandMsgXmd;
use elliptic_curve::{Field, PrimeField};
use image::EncodableLayout;
use k256::{ProjectivePoint, Scalar};
use rand_core::RngCore;
use sha2::Digest;
use sha3::Sha3_256;
use std::io;
use std::net::TcpStream;
use std::panic;

pub(crate) fn login(
    k3_c: [u8; 32],
    k3_s: [u8; 32],
    mut stream: &mut TcpStream,
    aead_nonce: &mut [u8; 12],
    ad: &&[u8; 13],
    g: ProjectivePoint,
    username: &str,
    pw: &str,
) -> bool {
    let username = username.as_bytes();
    let pw = pw.as_bytes();

    // ----------- OPRF stage -----------
    println!("Alice: OPRF stage");

    // Login request
    println!("Alice: Sending login request");
    let a = Scalar::random(&mut OsRng);
    let h_pw: ProjectivePoint =
        hash2curve_demo::<k256::Secp256k1, ExpandMsgXmd<Sha3_256>>(pw)
            .expect("hash2curve_demo (k256 + SHA3-256) failed");

    let mut msg = Vec::new();
    msg.extend_from_slice(b"Login;");
    msg.extend_from_slice(username);
    msg.extend_from_slice(b";");
    msg.extend_from_slice((h_pw * a).to_bytes().as_bytes());
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

    // Receive AEAD(k3_s, {{h_pw^as, enc_client_keys}}) message from Google
    println!("Alice: Waiting for login response");
    let msg = User::recv_bytes(&mut stream);
    let (nonce, aead_payload) = match reconstruct_aead_message(msg) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let decrypted_msg = match decrypt(&k3_s, &ad, &nonce, &aead_payload) {
        Ok(value) => value,
        Err(value) => return value,
    };
    if decrypted_msg.len() < MAC_LEN + ENC_CLIENT_KEYS_LEN {
        eprintln!("Alice: Decrypt error: received malformed ratchet payload (len={})", decrypted_msg.len());
        return true;
    }
    let (h_pw_as_bytes, rest_bytes) = decrypted_msg.split_at(MAC_LEN + 1);
    let h_pw_as = ProjectivePoint::from_bytes(h_pw_as_bytes.into()).unwrap();
    let (enc_client_keys, enc_client_keys_nonce) = rest_bytes.split_at(ENC_CLIENT_KEYS_LEN + 1);

    // Decrypt enc_client_keys and verify correctness
    println!("Alice: Decrypting client keys");
    let h_pw_s = h_pw_as * a.invert().unwrap();
    let rw = Sha3_256::digest([pw.as_bytes(), h_pw_s.to_bytes().as_bytes()].concat());
    let (rw_key, _) = crypto::key_schedule::extract(None, rw.as_bytes());
    let client_key_info = match crypto::aead::decrypt(rw_key.as_ref(), &enc_client_keys_nonce.try_into().unwrap(), enc_client_keys.as_bytes(), ad.as_ref()) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("Alice: Login error: Incorrect password or corrupted data");
            return true;
        }
    };

    let alice_lsk_c_bytes: [u8; 32] = client_key_info[33..65].try_into().unwrap();
    let lsk_c: Scalar = Scalar::from_repr(alice_lsk_c_bytes.into()).expect("invalid Scalar encoding for alice_lsk_c");
    let _lpk_c: ProjectivePoint = ProjectivePoint::from_bytes(client_key_info[..33].try_into().unwrap()).unwrap();
    let lpk_s: ProjectivePoint = ProjectivePoint::from_bytes(client_key_info[65..98].try_into().unwrap()).unwrap();

    // ----------- AKE stage: 3DH -----------
    println!("Alice: AKE stage");

    let x = Scalar::random(&mut OsRng);

    // Send ephemeral_pk to Google
    println!("Alice: Sending ephemeral_pk");
    let mut msg = Vec::new();
    msg.extend_from_slice((g * x).to_bytes().as_bytes());
    OsRng.fill_bytes(aead_nonce);
    let cypher_text = match encrypt(&k3_c, &aead_nonce, &ad, msg) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let msg = Message::AeadCiphertext {
        nonce: *aead_nonce,
        aead_payload: cypher_text
    };
    User::send_bytes(&mut stream, &msg);

    // Receive ephemeral_pk from Google
    println!("Alice: Waiting for ephemeral_pk");
    let msg = User::recv_bytes(&mut stream);
    let (nonce, aead_payload) = match msg {
        Message::AeadCiphertext { nonce, aead_payload } => (nonce, aead_payload),
        _ => panic!("Alice: Unexpected message"),
    };
    let decrypted_msg = match decrypt(&k3_s, &ad, &nonce, &aead_payload) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let large_y: ProjectivePoint = ProjectivePoint::from_bytes(decrypted_msg.as_slice().try_into().unwrap()).unwrap();

    // 3DH-KClient
    println!("Alice: Calculating SK");
    let mut key_input = Vec::new();
    key_input.extend_from_slice((lpk_s * x).to_bytes().as_bytes());
    key_input.extend_from_slice((large_y * x).to_bytes().as_bytes());
    key_input.extend_from_slice((large_y * lsk_c).to_bytes().as_bytes());
    let (sk, _) = crypto::key_schedule::extract(None, key_input.as_bytes());

    // ----------- Key Confirmation -----------
    println!("Alice: Key Confirmation stage");

    // Calculate mac_c
    println!("Alice: Calculating mac_c");
    let (_, hk) = crypto::key_schedule::extract(None, sk.as_bytes());
    let combined_key = crypto::key_schedule::expand::<64>(&hk, b"Key Confirmation").unwrap();
    let (kc, ks) = combined_key.split_at(32);

    let mac_c = compute_hmac(kc.as_bytes(), b"Client KC");
    let expected_mac_s = compute_hmac(ks.as_bytes(), b"Server KC");

    // Send mac_c to Google
    println!("Alice: Sending mac_c");
    OsRng.fill_bytes(aead_nonce);
    let cypher_text = match encrypt(&k3_c, &aead_nonce, &ad, mac_c) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let msg = Message::AeadCiphertext {
        nonce: *aead_nonce,
        aead_payload: cypher_text
    };
    User::send_bytes(&mut stream, &msg);

    // Receive mac_s from Google
    println!("Alice: Waiting for mac_s");
    let msg = User::recv_bytes(&mut stream);
    let (nonce, aead_payload) = match reconstruct_aead_message(msg) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let mac_s = match decrypt(&k3_s, &ad, &nonce, &aead_payload) {
        Ok(value) => value,
        Err(value) => return value,
    };

    // Verify mac_s
    println!("Alice: Verifying mac_s");
    assert!(verify_hmac(
        ks.as_bytes(),
        b"Server KC",
        mac_s.as_bytes()
    ));
    assert_eq!(mac_s.as_bytes(), expected_mac_s.as_bytes());
    println!("Alice: Valid MACs received.\n\n");

// End of login -----------------------------------------------------------------------------------------------------------
// Start communication -----------------------------------------------------------------------------------------------------------

    // ----------- Double Ratchet -----------
    println!("Alice: Double Ratchet stage");

    let mut rk_i = sk;
    let mut large_y_i = large_y;
    let mut _x_i = x;

    #[cfg(not(test))]
    loop {
        println!("Enter a message to send to Google: ");
        let mut message_from_user = String::new();
        io::stdin()
            .read_line(&mut message_from_user)
            .expect("Error reading message_from_user");
        let message_from_user = message_from_user.trim();

        let (x_i_plus_1, large_y_plus_one, rk_i_plus_2, _) = match double_ratchet_iteration(&mut stream, aead_nonce, &ad, g, rk_i, large_y_i, message_from_user) {
            Ok(value) => value,
            Err(value) => return value,
        };

        rk_i = rk_i_plus_2.into();
        large_y_i = large_y_plus_one;
        _x_i = x_i_plus_1;
    }

    #[cfg(test)]
    {
        return false
    }
}