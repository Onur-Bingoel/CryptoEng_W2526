use crate::crypto;
use crate::crypto::hmac::{compute_hmac, verify_hmac};
use crate::crypto::key_schedule::{key_schedule_1, key_schedule_2, key_schedule_3};
use crate::crypto::participant::{Message, User, CA};
use crate::server::google;
use aes_gcm::aead::OsRng;
use hmac::digest::Digest;
use image::EncodableLayout;
use kem::Encapsulate;
use ml_dsa::signature::Signer;
use ml_dsa::{KeyGen, MlDsa65, Seed};
use ml_kem::kem::EncapsulationKey;
use ml_kem::{EncodedSizeUser, MlKem768Params};
use rand_core::RngCore;
use sha2::Sha256;
use std::net::TcpStream;
use std::panic;
use std::sync::atomic::Ordering;
use crate::server::google::println;

pub(crate) fn pq_tls(
    mut stream: &mut TcpStream,
    ca: &mut CA,
    ad: &[u8; 13]
) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32]) {

    let mut nonce_s: [u8; 8] = [0u8; 8];
    OsRng.fill_bytes(&mut nonce_s);
    let mut aead_nonce: [u8; 12] = [0u8; 12];

    // Receive PqtlsClientHello from Alive
    println("Google: Waiting for PqtlsClientHello from Alice");
    let msg = User::recv_bytes(&mut stream);
    let (nonce_c, ek_bytes) = match msg {
        Message::PqtlsClientHello { nonce_c, ek } => (nonce_c, ek),
        _ => {
            match msg {
                Message::Reset {} => (),
                _ => {
                    eprintln!("Google: Unexpected message");
                    return ([0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32]);
                }
            }
            google::RECEIVED_RESET.store(true, Ordering::Relaxed);
            panic!("Google: Unexpected message")
        },
    };
    const EK768_LEN: usize = 1184;
    let ek_arr: [u8; EK768_LEN] = ek_bytes.as_slice().try_into()
        .expect("ungültige EncapsulationKey-Bytes (falsche Länge)");
    let ek = EncapsulationKey::<MlKem768Params>::from_bytes((&ek_arr).as_ref());

    // Generate key pair and calculate shared key and ciphertext
    println("Google: Generating key pair and calculating shared key and ciphertext");
    let key_pair = MlDsa65::from_seed(&Seed::default());
    let (ct, shared_key) = ek.encapsulate(&mut OsRng).unwrap();

    // Calculate K1_c, K1_s, K2_c, K2_s
    println("Google: Calculating K1_c, K1_s, K2_c, K2_s");
    let (k1_c, k1_s) = key_schedule_1(shared_key.as_bytes());
    let (k2_c, k2_s) = key_schedule_2(
        nonce_c.clone().as_bytes(),
        ek.as_bytes().as_bytes(),
        nonce_s.clone().as_bytes(),
        key_pair.verifying_key().encode().as_bytes(),
        shared_key.as_bytes(),
    );

    // Get certificate for google's public key
    println("Google: Getting certificate for google's public key");
    let cert = ca.generate_certificate(key_pair.verifying_key().encode().as_bytes());

    // Calculate google's signature
    println("Google: Calculating google's signature");
    let mut sign_digest_input = Vec::new();
    sign_digest_input.extend_from_slice(nonce_c.clone().as_bytes());
    sign_digest_input.extend_from_slice(ek.as_bytes().as_bytes());
    sign_digest_input.extend_from_slice(nonce_s.as_bytes());
    sign_digest_input.extend_from_slice(key_pair.verifying_key().encode().as_bytes());
    sign_digest_input.extend_from_slice(cert.encode().as_bytes());

    let google_sign = key_pair.signing_key().sign(&Sha256::digest(&sign_digest_input));

    // Calculate google's MAC tag
    println("Google: Calculating google's MAC tag");
    let mut mac_s_input = Vec::new();
    mac_s_input.extend_from_slice(nonce_c.clone().as_bytes());
    mac_s_input.extend_from_slice(ek.as_bytes().as_bytes());
    mac_s_input.extend_from_slice(nonce_s.as_bytes());
    mac_s_input.extend_from_slice(key_pair.verifying_key().encode().as_bytes());
    mac_s_input.extend_from_slice(google_sign.encode().as_bytes());
    mac_s_input.extend_from_slice(cert.encode().as_bytes());
    mac_s_input.extend_from_slice(b"ServerMAC");

    let mac_s = compute_hmac(&k2_s, &Sha256::digest(&mac_s_input));

    // Calculate K3_c, K3_s
    println("Google: Calculating K3_c, K3_s");
    let (k3_c, k3_s) = key_schedule_3(
        nonce_c.clone().as_bytes(),
        ek.as_bytes().as_bytes(),
        nonce_s.as_bytes(),
        key_pair.verifying_key().encode().as_bytes(),
        shared_key.as_bytes(),
        google_sign.encode().as_bytes(),
        cert.encode().as_bytes(),
        mac_s.as_bytes(),
    );

    // Send nonce_s, ct, verifying_key from Google to Alice
    println("Google: Sending nonce_s, ct, verifying_key from Google to Alice");
    let msg = Message::PqtlsServerHello {
        nonce_s: nonce_s.to_vec(),
        ct: ct.as_bytes().to_vec(),
        verifying_key: key_pair.verifying_key().encode().as_bytes().to_vec(),
    };
    User::send_bytes(&mut stream, &msg);

    // Send AEAD(k1_s, {{cert , google_sign, mac_s}}) message from Google to Alice
    println("Google: Sending AEAD(k1_s, {{cert , google_sign, mac_s}}) message from Google to Alice");
    let mut msg = Vec::new();
    msg.extend_from_slice(cert.encode().as_bytes());
    msg.extend_from_slice(google_sign.encode().as_bytes());
    msg.extend_from_slice(mac_s.as_bytes());
    OsRng.fill_bytes(&mut aead_nonce);
    let cypher_text: Vec<u8> = match crypto::aead::encrypt(&k1_s, &aead_nonce, msg.as_bytes(), &ad.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Google: Encrypt error: {e}");
            return ([0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32]);
        }
    };

    let msg = Message::AeadCiphertext {
        nonce: aead_nonce,
        aead_payload: cypher_text,
    };
    User::send_bytes(&mut stream, &msg);


    // Receive and decrypt the AEAD message
    println("Google: Receiving and decrypting the AEAD message");
    let msg = User::recv_bytes(&mut stream);
    let (nonce, aead_payload) = match msg {
        Message::AeadCiphertext { nonce, aead_payload } => (nonce, aead_payload),
        _ => {
            match msg {
                Message::Reset {} => (),
                _ => {
                    eprintln!("Google: Unexpected message");
                    return ([0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32]);
                }
            }
            google::RECEIVED_RESET.store(true, Ordering::Relaxed);
            panic!("Google: Unexpected message")
        },
    };
    let decrypted_msg: Vec<u8> = match crypto::aead::decrypt(&k1_c, &nonce, &aead_payload, &ad.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Google: Decrypt error: {e}");
            return ([0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32]);
        }
    };

    // Verify the MAC tag from Alice
    println("Google: Verifying the MAC tag from Alice");
    let mut expected_mac_c_input = Vec::new();
    expected_mac_c_input.extend_from_slice(nonce_c.clone().as_bytes());
    expected_mac_c_input.extend_from_slice(ek.as_bytes().as_bytes());
    expected_mac_c_input.extend_from_slice(nonce_s.as_bytes());
    expected_mac_c_input.extend_from_slice(key_pair.verifying_key().encode().as_bytes());
    expected_mac_c_input.extend_from_slice(google_sign.encode().as_bytes());
    expected_mac_c_input.extend_from_slice(cert.encode().as_bytes());
    expected_mac_c_input.extend_from_slice(b"ClientMAC");

    assert!(verify_hmac(&k2_c, &Sha256::digest(&expected_mac_c_input), decrypted_msg.as_bytes()));

    (k1_c, k1_s, k2_c, k2_s, k3_c, k3_s)
}