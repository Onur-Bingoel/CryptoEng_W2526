use image::EncodableLayout;
use kem::{Decapsulate, Encapsulate};
use ml_dsa::signature::{Signer, Verifier};
use ml_kem::{KemCore, MlKem768};
use sha2::{Digest, Sha256};
use std::thread;
use crate::crypto::{graph, participant};
use crate::crypto::graph::render_graph;
use crate::crypto::hmac::{compute_hmac, verify_hmac};
use crate::crypto::key_schedule::{key_schedule_1, key_schedule_2, key_schedule_3};
use crate::crypto::participant::{User};
mod crypto;

fn main() {
    thread::Builder::new()
        .stack_size(8 * 1024 * 1024) // z.B. 8 MB
        .spawn(run)
        .expect("Thread-Start fehlgeschlagen")
        .join()
        .expect("Thread-Abbruch");
}

// TODO: pk and sk don't correctly get used, because they are from dsa while shared secret is from ml_kem
fn run() {
    let mut graph = graph::Graph::new();
    let mut rng = rand::thread_rng();
    let nonce = [0u8; 12];

    println!("--- Initializing ---");
    let ca = participant::CA::new(rng.clone());
    let alice = User::new("Alice".into(), rng.clone(), &mut graph);
    let google = User::new("Google".into(), rng.clone(), &mut graph);

    let google_verifying_key_from_alice = alice.verifying_key();
    let alice_verifying_key_from_google = google.verifying_key();

// Alice ---------------------------------------------------------------------------------------------------
    let (alice_dk, alice_ek) = MlKem768::generate(&mut rng);

    alice.send_message("nonce_c, ek".to_string(), google.id(), &mut graph);
    println!("--- Sending nonce_c, ek from Alice to Google ---");
    let google_nonce_from_alice = alice.nonce();
    let google_ek_from_alice = alice_ek;

// Google ---------------------------------------------------------------------------------------------------
    let (google_ct, google_shared_key) = google_ek_from_alice.encapsulate(&mut rng).unwrap();

    // Calculate K1_c, K1_s, K2_c, K2_s
    let (google_k1_c, google_k1_s) = key_schedule_1(google_shared_key.as_bytes());
    let (google_k2_c, google_k2_s) = key_schedule_2(
        google_nonce_from_alice.clone().as_bytes(),
        google_verifying_key_from_alice.encode().as_bytes(),
        google.nonce().clone().as_bytes(),
        google.verifying_key().encode().as_bytes(),
        google_shared_key.as_bytes(),
    );

    // Get certificate for google's public key
    let google_cert = ca.generate_certificate(google.verifying_key().encode().as_bytes());

    // Calculate google's signature
    let mut sign_digest_input = Vec::new();
    sign_digest_input.extend_from_slice(google_nonce_from_alice.clone().as_bytes());
    sign_digest_input.extend_from_slice(google_verifying_key_from_alice.encode().as_bytes());
    sign_digest_input.extend_from_slice(google.nonce().as_bytes());
    sign_digest_input.extend_from_slice(google.verifying_key().encode().as_bytes());
    sign_digest_input.extend_from_slice(google_cert.encode().as_bytes());

    let google_sign = google.signing_key().sign(&Sha256::digest(&sign_digest_input));

    // Calculate google's MAC tag
    let mut mac_s_input = Vec::new();
    mac_s_input.extend_from_slice(google_nonce_from_alice.clone().as_bytes());
    mac_s_input.extend_from_slice(google_verifying_key_from_alice.encode().as_bytes());
    mac_s_input.extend_from_slice(google.nonce().as_bytes());
    mac_s_input.extend_from_slice(google.verifying_key().encode().as_bytes());
    mac_s_input.extend_from_slice(google_sign.encode().as_bytes());
    mac_s_input.extend_from_slice(google_cert.encode().as_bytes());
    mac_s_input.extend_from_slice(b"ServerMAC");

    let google_mac_s = compute_hmac(&google_k2_s, &Sha256::digest(&mac_s_input));

    // Calculate K3_c, K3_s
    let (google_k3_c, google_k3_s) = key_schedule_3(
        google_nonce_from_alice.clone().as_bytes(),
        google_verifying_key_from_alice.encode().as_bytes(),
        google.nonce().as_bytes(),
        google.verifying_key().encode().as_bytes(),
        google_shared_key.as_bytes(),
        google_sign.encode().as_bytes(),
        google_cert.encode().as_bytes(),
        google_mac_s.as_bytes(),
    );

    google.send_message("nonce_s, ct".to_string(), alice.id(), &mut graph);
    println!("--- Sending nonce_s, ct from Google to Alice ---");
    let alice_nonce_from_google = google.nonce();
    let alice_ct_from_google = google_ct;

    google.send_message("AEAD(k1_s, {{cert_pk_s , sign_s, mac_s}})".to_string(), alice.id(), &mut graph);
    println!("--- Sending AEAD(k1_s, {{cert_pk_s , sign_s, mac_s}}) from Google to Alice ---");
    let mut msg = Vec::new();
    msg.extend_from_slice(google_cert.encode().as_bytes());
    msg.extend_from_slice(google_sign.encode().as_bytes());
    msg.extend_from_slice(google_mac_s.as_bytes());
    let mut google_ad = Vec::new();  // ("Alice", "Google", A, G) Set the associate data as "('Alice', 'Google', A, G)", where A and G are the pk's of ALice and Google, respectively
    google_ad.extend_from_slice(b"Alice,Google,");
    google_ad.extend_from_slice(google_verifying_key_from_alice.encode().as_bytes());
    google_ad.extend_from_slice(b",");
    google_ad.extend_from_slice(google.verifying_key().encode().as_bytes());

    let cypher_text_1: Vec<u8> = match crypto::aead::encrypt(&google_k1_s, &nonce, msg.as_bytes(), &google_ad) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Encrypt error: {e}");
            return;
        }
    };

// Alice ---------------------------------------------------------------------------------------------------

    let alice_shared_key = alice_dk.decapsulate(&alice_ct_from_google).unwrap();
    let (alice_k1_c, alice_k1_s) = key_schedule_1(alice_shared_key.as_bytes());
    let (alice_k2_c, alice_k2_s) = key_schedule_2(
        alice.nonce().clone().as_bytes(),
        alice.verifying_key().encode().as_bytes(),
        alice_nonce_from_google.clone().as_bytes(),
        alice_verifying_key_from_google.encode().as_bytes(),
        alice_shared_key.as_bytes(),
    );

    // Decrypt the received AEAD message
    let mut alice_ad = Vec::new();  // ("Alice", "Google", A, G) Set the associate data as "('Alice', 'Google', A, G)", where A and G are the pk's of ALice and Google, respectively
    alice_ad.extend_from_slice(b"Alice,Google,");
    alice_ad.extend_from_slice(alice.verifying_key().encode().as_bytes());
    alice_ad.extend_from_slice(b",");
    alice_ad.extend_from_slice(alice_verifying_key_from_google.encode().as_bytes());
    let decrypted_msg_1: Vec<u8> = match crypto::aead::decrypt(&alice_k1_s, &nonce, &cypher_text_1, &alice_ad) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Decrypt error: {e}");
            return;
        }
    };

    let mac_len = 32;
    let mac_start = decrypted_msg_1.len() - mac_len;
    let alice_mac_from_google: Vec<u8> = decrypted_msg_1[mac_start..].to_vec();

    let rest = &decrypted_msg_1[..mac_start];
    let half = rest.len() / 2;
    let alice_cert_from_google: Vec<u8> = rest[..half].to_vec();
    let alice_sign_from_google: Vec<u8> = rest[half..].to_vec();

    // Calculate K3_c, K3_s
    let (alice_k3_c, alice_k3_s) = key_schedule_3(
        alice.nonce().clone().as_bytes(),
        alice.verifying_key().encode().as_bytes(),
        alice_nonce_from_google.as_bytes(),
        alice_verifying_key_from_google.encode().as_bytes(),
        alice_shared_key.as_bytes(),
        alice_sign_from_google.as_bytes(),
        alice_cert_from_google.as_bytes(),
        alice_mac_from_google.as_bytes(),
    );

    // Verify the signature, certificate and MAC tag from google
    let mut expected_sign_msg = Vec::new();
    expected_sign_msg.extend_from_slice(alice.nonce().clone().as_bytes());
    expected_sign_msg.extend_from_slice(alice.verifying_key().encode().as_bytes());
    expected_sign_msg.extend_from_slice(alice_nonce_from_google.as_bytes());
    expected_sign_msg.extend_from_slice(alice_verifying_key_from_google.encode().as_bytes());
    expected_sign_msg.extend_from_slice(alice_cert_from_google.as_bytes());
    let mut expected_mac_s_input = Vec::new();
    expected_mac_s_input.extend_from_slice(alice.nonce().clone().as_bytes());
    expected_mac_s_input.extend_from_slice(alice.verifying_key().encode().as_bytes());
    expected_mac_s_input.extend_from_slice(alice_nonce_from_google.as_bytes());
    expected_mac_s_input.extend_from_slice(alice_verifying_key_from_google.encode().as_bytes());
    expected_mac_s_input.extend_from_slice(alice_sign_from_google.as_bytes());
    expected_mac_s_input.extend_from_slice(alice_cert_from_google.as_bytes());
    expected_mac_s_input.extend_from_slice(b"ServerMAC");

    assert!(alice_verifying_key_from_google.verify(&Sha256::digest(&expected_sign_msg), &google_sign).is_ok());     // TODO: google_sign should be alice_sign_from_google
    assert!(ca.verifying_key().verify(alice_verifying_key_from_google.encode().as_bytes(), &google_cert).is_ok());  // TODO: google_cert should be alice_cert_from_google
    assert!(verify_hmac(&alice_k2_s, &Sha256::digest(&expected_mac_s_input), alice_mac_from_google.as_bytes()));

    // Generate MAC
    let mut mac_c_input = Vec::new();
    mac_c_input.extend_from_slice(alice.nonce().clone().as_bytes());
    mac_c_input.extend_from_slice(alice.verifying_key().encode().as_bytes());
    mac_c_input.extend_from_slice(alice_nonce_from_google.as_bytes());
    mac_c_input.extend_from_slice(alice_verifying_key_from_google.encode().as_bytes());
    mac_c_input.extend_from_slice(alice_sign_from_google.as_bytes());
    mac_c_input.extend_from_slice(alice_cert_from_google.as_bytes());
    mac_c_input.extend_from_slice(b"ClientMAC");

    let alice_mac_c = compute_hmac(&google_k2_s, &Sha256::digest(&mac_c_input));

    alice.send_message("AEAD(k1_c, {{alice_mac_c}})".to_string(), google.id(), &mut graph);
    println!("--- Sending AEAD(k1_c, {{alice_mac_c}}) from Alice to Google ---");
    let cypher_text_2: Vec<u8> = match crypto::aead::encrypt(&alice_k1_c, &nonce, alice_mac_c.as_bytes(), &alice_ad) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Encrypt error: {e}");
            return;
        }
    };

// Google ---------------------------------------------------------------------------------------------------

    // Decrypt the received AEAD message
    let decrypted_msg_2: Vec<u8> = match crypto::aead::decrypt(&google_k1_c, &nonce, &cypher_text_2, &google_ad) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Decrypt error: {e}");
            return;
        }
    };

    // Verify the MAC tag from Alice
    let mut expected_mac_c_input = Vec::new();
    expected_mac_c_input.extend_from_slice(google_nonce_from_alice.clone().as_bytes());
    expected_mac_c_input.extend_from_slice(google_verifying_key_from_alice.encode().as_bytes());
    expected_mac_c_input.extend_from_slice(google.nonce().as_bytes());
    expected_mac_c_input.extend_from_slice(google.verifying_key().encode().as_bytes());
    expected_mac_c_input.extend_from_slice(google_sign.encode().as_bytes());
    expected_mac_c_input.extend_from_slice(google_cert.encode().as_bytes());
    expected_mac_c_input.extend_from_slice(b"ClientMAC");

    assert!(verify_hmac(&google_k2_s, &Sha256::digest(&expected_mac_c_input), decrypted_msg_2.as_bytes()));

// END ---------------------------------------------------------------------------------------------------
    // Verify that both sides derived the same keys
    assert_eq!(alice_k1_c, google_k1_c);
    assert_eq!(alice_k1_s, google_k1_s);
    assert_eq!(alice_k2_c, google_k2_c);
    assert_eq!(alice_k2_s, google_k2_s);
    assert_eq!(alice_k3_c, google_k3_c);
    assert_eq!(alice_k3_s, google_k3_s);

    render_graph(&graph, "messages.png");
}