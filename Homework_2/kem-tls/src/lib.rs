mod crypto;
use crate::crypto::hmac::{compute_hmac, verify_hmac};
use crate::crypto::key_schedule::{extract, key_schedule_1, key_schedule_2, key_schedule_3};
use crate::crypto::participant::User;
use crate::crypto::participant;
use aead::rand_core::RngCore;
use image::EncodableLayout;
use kem::{Decapsulate, Encapsulate};
use ml_dsa::signature::Verifier;
use ml_kem::Ciphertext;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use sha2::{Digest, Sha256};

pub fn run(silent: bool) {
    let mut rng = rand::thread_rng();
    let nonce = [0u8; 12];
    let random_sign_value: [u8; 8] = rng.next_u64().to_le_bytes(); // There is no sign in the slides

    let ca = participant::CA::new(rng.clone());
    let alice = User::new("Alice".into(), rng.clone());
    let google = User::new("Google".into(), rng.clone());

    // Alice ---------------------------------------------------------------------------------------------------
    let (alice_dk, alice_ek) = MlKem768::generate(&mut rng);

    alice.send_message("nonce_c, ek".to_string(), google.name.clone(), silent);
    let google_nonce_from_alice = alice.nonce();
    let google_ek_from_alice = alice_ek.clone();

    // Google ---------------------------------------------------------------------------------------------------
    let (google_dk, google_ek) = MlKem768::generate(&mut rng);
    let (google_ct, google_first_k) = google_ek_from_alice.encapsulate(&mut rng).unwrap();

    // Calculate K1_c, K1_s, K2_c, K2_s
    let (google_k1_c, google_k1_s) = key_schedule_1(google_first_k.as_bytes());

    // Get certificate for google's public key
    let google_cert = ca.generate_certificate(google_ek.as_bytes().as_bytes());

    let mut google_ad = Vec::new();  // ("Alice", "Google", A, G) Set the associate data as "('Alice', 'Google', A, G)", where A and G are the pk's of ALice and Google, respectively
    google_ad.extend_from_slice(b"Alice,Google,");
    google_ad.extend_from_slice(google_ek_from_alice.as_bytes().as_bytes());
    google_ad.extend_from_slice(b",");
    google_ad.extend_from_slice(google_ek.as_bytes().as_bytes());

    google.send_message("nonce_s, ct".to_string(), alice.name.clone(), silent);
    let alice_nonce_from_google = google.nonce();
    let alice_ct_from_google = google_ct;

    google.send_message("ek".to_string(), alice.name.clone(), silent);
    let alice_ek_from_google = google_ek.clone();

    google.send_message("AEAD(k1_s, {{cert_pk_s}})".to_string(), alice.name.clone(), silent);
    let cypher_text_1: Vec<u8> = match crypto::aead::encrypt(&google_k1_s, &nonce, google_cert.encode().as_bytes(), &google_ad) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Encrypt error: {e}");
            return;
        }
    };

    // Alice ---------------------------------------------------------------------------------------------------
    let alice_first_k = alice_dk.decapsulate(&alice_ct_from_google).unwrap();
    let (alice_k1_c, alice_k1_s) = key_schedule_1(alice_first_k.as_bytes());
    let (alice_ct, alice_second_k) = alice_ek_from_google.encapsulate(&mut rng).unwrap();

    // Decrypt the received AEAD message
    let mut alice_ad = Vec::new();  // ("Alice", "Google", A, G) Set the associate data as "('Alice', 'Google', A, G)", where A and G are the pk's of ALice and Google, respectively
    alice_ad.extend_from_slice(b"Alice,Google,");
    alice_ad.extend_from_slice(alice_ek.as_bytes().as_bytes());
    alice_ad.extend_from_slice(b",");
    alice_ad.extend_from_slice(alice_ek_from_google.as_bytes().as_bytes());
    let alice_cert_from_google: Vec<u8> = match crypto::aead::decrypt(&alice_k1_s, &nonce, &cypher_text_1, &alice_ad) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Decrypt error: {e}");
            return;
        }
    };
    assert!(ca.verifying_key().verify(alice_ek_from_google.as_bytes().as_bytes(), &google_cert).is_ok());  // google_cert should be alice_cert_from_google, but because of type mismatch google_cert was used (They should be equivalent)

    let (alice_shared_key_prk, _) = extract(Some(alice_first_k.as_bytes()), alice_second_k.as_bytes());

    let (alice_k2_c, alice_k2_s) = key_schedule_2(
        alice.nonce().clone().as_bytes(),
        alice_ek.as_bytes().as_bytes(),
        alice_nonce_from_google.clone().as_bytes(),
        alice_ek_from_google.as_bytes().as_bytes(),
        alice_shared_key_prk.as_bytes(),
    );

    // Generate MAC
    let mut mac_c_input = Vec::new();
    mac_c_input.extend_from_slice(alice.nonce().clone().as_bytes());
    mac_c_input.extend_from_slice(alice_ek.as_bytes().as_bytes());
    mac_c_input.extend_from_slice(alice_nonce_from_google.as_bytes());
    mac_c_input.extend_from_slice(alice_ek_from_google.as_bytes().as_bytes());
    mac_c_input.extend_from_slice(random_sign_value.as_bytes()); // TODO: random_sign_value because there is no server signature in this scheme
    mac_c_input.extend_from_slice(alice_cert_from_google.as_bytes());
    mac_c_input.extend_from_slice(b"ClientMAC");

    let alice_mac_c = compute_hmac(&alice_k2_c, &Sha256::digest(&mac_c_input));

    alice.send_message("AEAD(k1_c, {{alice_ct}})".to_string(), google.name.clone(), silent);
    let cypher_text_2: Vec<u8> = match crypto::aead::encrypt(&alice_k1_c, &nonce, alice_ct.as_bytes(), &alice_ad) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Encrypt error: {e}");
            return;
        }
    };

    alice.send_message("AEAD(k2_c, {{alice_mac_c}})".to_string(), google.name.clone(), silent);
    let cypher_text_3: Vec<u8> = match crypto::aead::encrypt(&alice_k2_c, &nonce, alice_mac_c.as_bytes(), &alice_ad) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Encrypt error: {e}");
            return;
        }
    };

    // Google ---------------------------------------------------------------------------------------------------

    // Decrypt the received AEAD messages
    let decrypted_ciphertext_bytes: Vec<u8> = match crypto::aead::decrypt(&google_k1_c, &nonce, &cypher_text_2, &google_ad) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Decrypt error: {e}");
            return;
        }
    };
    let google_ct_from_alice = Ciphertext::<MlKem768>::try_from(decrypted_ciphertext_bytes.as_slice()).unwrap();
    let google_second_k = google_dk.decapsulate(&google_ct_from_alice).unwrap();
    let (google_shared_key_prk, _) = extract(Some(google_first_k.as_bytes()), google_second_k.as_bytes());
    let (google_k2_c, google_k2_s) = key_schedule_2(
        google_nonce_from_alice.clone().as_bytes(),
        google_ek_from_alice.as_bytes().as_bytes(),
        google.nonce().clone().as_bytes(),
        google_ek.as_bytes().as_bytes(),
        google_shared_key_prk.as_bytes(),
    );

    let google_mac_c_from_alice: Vec<u8> = match crypto::aead::decrypt(&google_k2_c, &nonce, &cypher_text_3, &google_ad) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Decrypt error: {e}");
            return;
        }
    };

    // Verify the MAC tag from Alice
    let mut expected_mac_c_input = Vec::new();
    expected_mac_c_input.extend_from_slice(google_nonce_from_alice.clone().as_bytes());
    expected_mac_c_input.extend_from_slice(google_ek_from_alice.as_bytes().as_bytes());
    expected_mac_c_input.extend_from_slice(google.nonce().as_bytes());
    expected_mac_c_input.extend_from_slice(google_ek.as_bytes().as_bytes());
    expected_mac_c_input.extend_from_slice(random_sign_value.as_bytes()); // TODO: random_sign_value because there is no server signature in this scheme
    expected_mac_c_input.extend_from_slice(google_cert.encode().as_bytes());
    expected_mac_c_input.extend_from_slice(b"ClientMAC");

    assert!(verify_hmac(&google_k2_c, &Sha256::digest(&expected_mac_c_input), google_mac_c_from_alice.as_bytes()));

    // Calculate google's MAC tag
    let mut mac_s_input = Vec::new();
    mac_s_input.extend_from_slice(google_nonce_from_alice.clone().as_bytes());
    mac_s_input.extend_from_slice(google_ek_from_alice.as_bytes().as_bytes());
    mac_s_input.extend_from_slice(google.nonce().as_bytes());
    mac_s_input.extend_from_slice(google_ek.as_bytes().as_bytes());
    mac_s_input.extend_from_slice(random_sign_value.as_bytes()); // TODO: random_sign_value because there is no server signature in this scheme
    mac_s_input.extend_from_slice(google_cert.encode().as_bytes());
    mac_s_input.extend_from_slice(b"ServerMAC");

    let google_mac_s = compute_hmac(&google_k2_s, &Sha256::digest(&mac_s_input));

    google.send_message("AEAD(k2_s, {{mac_s}})".to_string(), alice.name.clone(), silent);
    let cypher_text_4: Vec<u8> = match crypto::aead::encrypt(&google_k2_s, &nonce, google_mac_s.as_bytes(), &google_ad) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Encrypt error: {e}");
            return;
        }
    };

    // Alice ---------------------------------------------------------------------------------------------------

    let alice_mac_s_from_google: Vec<u8> = match crypto::aead::decrypt(&alice_k2_s, &nonce, &cypher_text_4, &alice_ad) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Decrypt error: {e}");
            return;
        }
    };

    let mut expected_mac_s_input = Vec::new();
    expected_mac_s_input.extend_from_slice(alice.nonce().clone().as_bytes());
    expected_mac_s_input.extend_from_slice(alice_ek.as_bytes().as_bytes());
    expected_mac_s_input.extend_from_slice(alice_nonce_from_google.as_bytes());
    expected_mac_s_input.extend_from_slice(alice_ek_from_google.as_bytes().as_bytes());
    expected_mac_s_input.extend_from_slice(random_sign_value.as_bytes()); // TODO: random_sign_value because there is no server signature in this scheme
    expected_mac_s_input.extend_from_slice(alice_cert_from_google.as_bytes());
    expected_mac_s_input.extend_from_slice(b"ServerMAC");

    assert!(verify_hmac(&alice_k2_s, &Sha256::digest(&expected_mac_s_input), alice_mac_s_from_google.as_bytes()));

    // Calculate K3_c, K3_s
    let (alice_k3_c, alice_k3_s) = key_schedule_3(
        alice.nonce().clone().as_bytes(),
        alice_ek.as_bytes().as_bytes(),
        alice_nonce_from_google.as_bytes(),
        alice_ek_from_google.as_bytes().as_bytes(),
        alice_shared_key_prk.as_bytes(),
        random_sign_value.as_bytes(),  // TODO: There is no alice_sign_from_google
        alice_cert_from_google.as_bytes(),
        alice_mac_s_from_google.as_bytes(),
    );


    // Google ---------------------------------------------------------------------------------------------------

    // Calculate K3_c, K3_s
    let (google_k3_c, google_k3_s) = key_schedule_3(
        google_nonce_from_alice.clone().as_bytes(),
        google_ek_from_alice.as_bytes().as_bytes(),
        google.nonce().as_bytes(),
        google_ek.as_bytes().as_bytes(),
        google_shared_key_prk.as_bytes(),
        random_sign_value.as_bytes(),  // TODO: There is no google_sign
        google_cert.encode().as_bytes(),
        google_mac_s.as_bytes(),
    );

    // END ---------------------------------------------------------------------------------------------------
    // Verify that both sides derived the same keys
    assert_eq!(alice_k1_c, google_k1_c);
    assert_eq!(alice_k1_s, google_k1_s);
    assert_eq!(alice_k2_c, google_k2_c);
    assert_eq!(alice_k2_s, google_k2_s);
    assert_eq!(alice_k3_c, google_k3_c);
    assert_eq!(alice_k3_s, google_k3_s);
}