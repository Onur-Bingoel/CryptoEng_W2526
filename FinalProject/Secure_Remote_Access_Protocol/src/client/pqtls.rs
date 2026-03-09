use crate::crypto;
use crate::crypto::hmac::{compute_hmac, verify_hmac};
use crate::crypto::key_schedule::{key_schedule_1, key_schedule_2, key_schedule_3};
use crate::crypto::participant::{Message, User, CA};
use aes_gcm::aead::OsRng;
use image::EncodableLayout;
use kem::Decapsulate;
use ml_dsa::signature::Verifier;
use ml_dsa::{EncodedVerifyingKey, VerifyingKey};
use ml_dsa::{MlDsa65, Signature};
use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem768};
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::panic;
use crate::client::alice;

pub(crate) fn pq_tls(
    mut stream: &mut TcpStream,
    ca: &mut CA,
    ad: &[u8; 13]
) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32]) {

    let mut nonce_c: [u8; 8] = [0u8; 8];
    OsRng.fill_bytes(&mut nonce_c);
    let mut aead_nonce: [u8; 12] = [0u8; 12];
    let (dk, ek) = MlKem768::generate(&mut OsRng);

    // Send nonce_c, ek to Google
    println!("Alice: Sending nonce_c and ek to Google");
    let msg = Message::PqtlsClientHello {
        nonce_c: nonce_c.to_vec(),
        ek: ek.as_bytes().to_vec(),
    };
    User::send_bytes(&mut stream, &msg);

    // Receive PqtlsServerHello from Alive
    println!("Alice: Waiting for PqtlsServerHello from Google");
    let msg = User::recv_bytes(&mut stream);
    let (nonce_s, ct_bytes, verifying_key_bytes) = match msg {
        Message::PqtlsServerHello { nonce_s, ct, verifying_key } => (nonce_s, ct, verifying_key),
        _ => {
            match msg {
                Message::Reset {} => (),
                _ => {
                    eprintln!("Alice: Unexpected message");
                    return ([0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32]);
                }
            }
            alice::RECEIVED_RESET.store(true, Ordering::Relaxed);
            panic!("Alice: Unexpected message")
        },
    };
    let verifying_key = VerifyingKey::<MlDsa65>::decode(
        &EncodedVerifyingKey::<MlDsa65>::try_from(verifying_key_bytes.as_slice())
            .expect("Invalid verifying key bytes"),
    );
    let ct = Ciphertext::<MlKem768>::try_from(ct_bytes.as_slice())
        .expect("ungültiger Ciphertext");

    // Calculate shared key and K1_c, K1_s, K2_c, K2_s
    println!("Alice: Calculating shared key and K1_c, K1_s, K2_c, K2_s");
    let shared_key = dk.decapsulate(&ct).unwrap();
    let (k1_c, k1_s) = key_schedule_1(shared_key.as_bytes());
    let (k2_c, k2_s) = key_schedule_2(
        nonce_c.clone().as_bytes(),
        ek.as_bytes().as_bytes(),
        nonce_s.clone().as_bytes(),
        verifying_key.encode().as_bytes(),
        shared_key.as_bytes(),
    );

    // Receive and decrypt the AEAD message
    println!("Alice: Waiting for AEAD message from Google");
    let msg = User::recv_bytes(&mut stream);
    let (nonce, aead_payload) = match msg {
        Message::AeadCiphertext { nonce, aead_payload } => (nonce, aead_payload),
        _ => {
            match msg {
                Message::Reset {} => (),
                _ => {
                    eprintln!("Alice: Unexpected message");
                    return ([0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32]);
                }
            }
            alice::RECEIVED_RESET.store(true, Ordering::Relaxed);
            panic!("Alice: Unexpected message")
        },
    };
    let decrypted_msg: Vec<u8> = match crypto::aead::decrypt(&k1_s, &nonce, &aead_payload, &ad.to_vec()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Alice: Decrypt error: {e}");
            return ([0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32]);
        }
    };

    let mac_len = 32;
    let mac_start = decrypted_msg.len() - mac_len;
    let google_mac: Vec<u8> = decrypted_msg[mac_start..].to_vec();

    let rest = &decrypted_msg[..mac_start];
    let half = rest.len() / 2;
    let cert_from_google_bytes: Vec<u8> = rest[..half].to_vec();
    let sign_from_google_bytes: Vec<u8> = rest[half..].to_vec();
    let cert: Signature<MlDsa65> = Signature::try_from(cert_from_google_bytes.as_slice()).unwrap();
    let google_sign: Signature<MlDsa65> = Signature::try_from(sign_from_google_bytes.as_slice()).unwrap();

    // Calculate K3_c, K3_s
    println!("Alice: Calculating K3_c, K3_s");
    let (k3_c, k3_s) = key_schedule_3(
        nonce_c.clone().as_bytes(),
        ek.as_bytes().as_bytes(),
        nonce_s.as_bytes(),
        verifying_key.encode().as_bytes(),
        shared_key.as_bytes(),
        google_sign.encode().as_bytes(),
        cert.encode().as_bytes(),
        google_mac.as_bytes(),
    );

    // Verify the signature, certificate and MAC tag from google
    println!("Alice: Verifying the signature, certificate and MAC tag from google");
    let mut expected_sign_msg = Vec::new();
    expected_sign_msg.extend_from_slice(nonce_c.clone().as_bytes());
    expected_sign_msg.extend_from_slice(ek.as_bytes().as_bytes());
    expected_sign_msg.extend_from_slice(nonce_s.as_bytes());
    expected_sign_msg.extend_from_slice(verifying_key.encode().as_bytes());
    expected_sign_msg.extend_from_slice(cert.encode().as_bytes());
    let mut expected_mac_s_input = Vec::new();
    expected_mac_s_input.extend_from_slice(nonce_c.clone().as_bytes());
    expected_mac_s_input.extend_from_slice(ek.as_bytes().as_bytes());
    expected_mac_s_input.extend_from_slice(nonce_s.as_bytes());
    expected_mac_s_input.extend_from_slice(verifying_key.encode().as_bytes());
    expected_mac_s_input.extend_from_slice(google_sign.encode().as_bytes());
    expected_mac_s_input.extend_from_slice(cert.encode().as_bytes());
    expected_mac_s_input.extend_from_slice(b"ServerMAC");

    assert!(verifying_key.verify(&Sha256::digest(&expected_sign_msg), &google_sign).is_ok());
    assert!(ca.verifying_key().verify(verifying_key.encode().as_bytes(), &cert).is_ok());
    assert!(verify_hmac(&k2_s, &Sha256::digest(&expected_mac_s_input), google_mac.as_bytes()));

    // Calculate alice's MAC tag
    println!("Alice: Calculating alice's MAC tag");
    let mut mac_c_input = Vec::new();
    mac_c_input.extend_from_slice(nonce_c.clone().as_bytes());
    mac_c_input.extend_from_slice(ek.as_bytes().as_bytes());
    mac_c_input.extend_from_slice(nonce_s.as_bytes());
    mac_c_input.extend_from_slice(verifying_key.encode().as_bytes());
    mac_c_input.extend_from_slice(google_sign.encode().as_bytes());
    mac_c_input.extend_from_slice(cert.encode().as_bytes());
    mac_c_input.extend_from_slice(b"ClientMAC");

    let mac_c = compute_hmac(&k2_c, &Sha256::digest(&mac_c_input));

    // Send AEAD(k1_c, {{alice_mac_c}}) message from Alice to Google
    println!("Alice: Sending AEAD(k1_c, {{alice_mac_c}}) message from Alice to Google");
    OsRng.fill_bytes(&mut aead_nonce);
    let cypher_text: Vec<u8> = match crypto::aead::encrypt(&k1_c, &aead_nonce, mac_c.as_bytes(), &ad.to_vec()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Alice: Encrypt error: {e}");
            return ([0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32]);
        }
    };

    let msg = Message::AeadCiphertext {
        nonce: aead_nonce,
        aead_payload: cypher_text,
    };
    User::send_bytes(&mut stream, &msg);


    (k1_c, k1_s, k2_c, k2_s, k3_c, k3_s)
}