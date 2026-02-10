use crate::crypto::hash2curve::hash2curve_demo;
use crate::crypto::participant::User;
use aes_gcm::aead::OsRng;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::hash2curve::ExpandMsgXmd;
use elliptic_curve::{Field, PrimeField};
use hmac::digest::Digest;
use image::EncodableLayout;
use k256::Scalar;
use sha3::Sha3_256;

mod crypto;

fn main() {

// Initialization -------------------------------------------------------------------------------------------

    let alice = User::new("Alice".into());
    let google = User::new("Google".into());

    let google_ad = b"Alice,Google,";
    let alice_ad = b"Alice,Google,";

    let nonce = [0u8; 12];

// Alice ---------------------------------------------------------------------------------------------------

    // Choose username and password
    let alice_pw: &[u8] = b"a random password";
    let alice_username: &[u8] = b"alice";
    let alice_h_pw: k256::ProjectivePoint =
        hash2curve_demo::<k256::Secp256k1, ExpandMsgXmd<Sha3_256>>(alice_pw)
            .expect("hash2curve_demo (k256 + SHA3-256) failed");

    alice.send_message("Username, pw".to_string(), google.name.clone(), false);
    let _google_username = alice_username;
    let google_pw = alice_pw;

// Google ---------------------------------------------------------------------------------------------------

    let google_s = k256::Scalar::random(&mut OsRng);
    let google_h_pw: k256::ProjectivePoint =
        hash2curve_demo::<k256::Secp256k1, ExpandMsgXmd<Sha3_256>>(google_pw)
            .expect("hash2curve_demo (k256 + SHA3-256) failed");

    // 𝒓𝒘 = 𝐻(𝒑𝒘, ℎ_𝒑𝒘^𝒔)
    let google_rw = Sha3_256::digest([google_pw.as_bytes(), (google_h_pw * google_s).to_bytes().as_bytes()].concat());

    let (google_rw_key, _) = crypto::key_schedule::extract(None, google_rw.as_bytes());
    let google_lsk_s = k256::Scalar::random(&mut OsRng);
    let google_lpk_s: k256::ProjectivePoint = google_h_pw * google_lsk_s;

    let google_lsk_c = k256::Scalar::random(&mut OsRng);
    let google_lpk_c: k256::ProjectivePoint = google_h_pw * google_lsk_c;

    let mut google_client_key_info = Vec::new();
    google_client_key_info.extend_from_slice(&google_lpk_c.to_bytes());
    google_client_key_info.extend_from_slice(&google_lsk_c.to_bytes());
    google_client_key_info.extend_from_slice(&google_lpk_s.to_bytes());

    let google_enc_client_keys = crypto::aead::encrypt(
        google_rw_key.as_ref(),
        &nonce,
        google_client_key_info.as_bytes(),
        google_ad,
    );

    // save login data for Alice

// Alice ---------------------------------------------------------------------------------------------------

    let alice_a = Scalar::random(&mut OsRng);

    // Login request
    alice.send_message("Username, h_pw^a".to_string(), google.name.clone(), false);
    let _google_username = alice_username;
    let google_h_pw_a = alice_h_pw * alice_a;

// Google ---------------------------------------------------------------------------------------------------

    // Answer login request
    let alice_h_pw_as = google_h_pw_a * google_s;
    let alice_enc_client_keys = google_enc_client_keys.clone();

// Alice ---------------------------------------------------------------------------------------------------

    let alice_h_pw_s = alice_h_pw_as * alice_a.invert().unwrap();
    let alice_rw = Sha3_256::digest([alice_pw.as_bytes(), alice_h_pw_s.to_bytes().as_bytes()].concat());
    let (alice_rw_key, _) = crypto::key_schedule::extract(None, alice_rw.as_bytes());
    let alice_client_key_info = crypto::aead::decrypt(alice_rw_key.as_ref(), &nonce, alice_enc_client_keys.unwrap().as_bytes(), alice_ad).unwrap();

    let alice_lsk_c_bytes: [u8; 32] = alice_client_key_info[33..65].try_into().unwrap();
    let alice_lsk_c: Scalar = Scalar::from_repr(alice_lsk_c_bytes.into()).expect("invalid Scalar encoding for alice_lsk_c");
    let _alice_lpk_c: k256::ProjectivePoint = k256::ProjectivePoint::from_bytes(alice_client_key_info[..33].try_into().unwrap()).unwrap();
    let alice_lpk_s: k256::ProjectivePoint = k256::ProjectivePoint::from_bytes(alice_client_key_info[65..98].try_into().unwrap()).unwrap();

    // Send ephemeral key to Google
    let alice_x = Scalar::random(&mut OsRng);
    alice.send_message("epk_c = X".to_string(), google.name.clone(), false);
    let google_epk_c = alice_h_pw * alice_x.clone();

// Google ---------------------------------------------------------------------------------------------------

    // Send ephemeral key to Alice
    let google_y = Scalar::random(&mut OsRng);
    google.send_message("epk_s = Y".to_string(), alice.name.clone(), false);
    let alice_epk_s = google_h_pw * google_y.clone();

// Alice ---------------------------------------------------------------------------------------------------

    let mut alice_key_input = Vec::new();
    alice_key_input.extend_from_slice((alice_lpk_s * alice_x).to_bytes().as_bytes());
    alice_key_input.extend_from_slice((alice_epk_s * alice_x).to_bytes().as_bytes());
    alice_key_input.extend_from_slice((alice_epk_s * alice_lsk_c).to_bytes().as_bytes());

    // 3DH-KClient(𝑎, 𝑥, 𝐵, 𝑌)
    let (alice_sk, _) = crypto::key_schedule::extract(None, alice_key_input.as_bytes());

    let (_, alice_hk) = crypto::key_schedule::extract(None, alice_sk.as_bytes());
    let alice_combined_key = crypto::key_schedule::expand::<64>(&alice_hk, b"Key Confirmation").unwrap();
    let (alice_kc, alice_ks) = alice_combined_key.split_at(32);

    let alice_mac_c = crypto::hmac::compute_hmac(alice_kc.as_bytes(), b"Client KC");
    let alice_expected_mac_s = crypto::hmac::compute_hmac(alice_ks.as_bytes(), b"Server KC");

    // Send MAC to Google
    alice.send_message("mac_c".to_string(), google.name.clone(), false);
    let google_mac_c = alice_mac_c.clone();

// Google ---------------------------------------------------------------------------------------------------

    let mut google_key_input = Vec::new();
    google_key_input.extend_from_slice((google_epk_c * google_lsk_s).to_bytes().as_bytes());
    google_key_input.extend_from_slice((google_epk_c * google_y).to_bytes().as_bytes());
    google_key_input.extend_from_slice((google_lpk_c * google_y).to_bytes().as_bytes());

    // 3DH-KServer (𝑏, 𝑦, 𝐴, 𝑋)
    let (google_sk, _) = crypto::key_schedule::extract(None, google_key_input.as_bytes());

    let (_, google_hk) = crypto::key_schedule::extract(None, google_sk.as_bytes());
    let google_combined_key = crypto::key_schedule::expand::<64>(&google_hk, b"Key Confirmation").unwrap();
    let (google_kc, google_ks) = google_combined_key.split_at(32);

    let google_mac_s = crypto::hmac::compute_hmac(google_ks.as_bytes(), b"Server KC");
    let google_expected_mac_c = crypto::hmac::compute_hmac(google_kc.as_bytes(), b"Client KC");

    // Send MAC to Alice
    google.send_message("mac_s".to_string(), alice.name.clone(), false);
    let alice_mac_s = google_mac_s.clone();

// Alice ---------------------------------------------------------------------------------------------------

    assert!(crypto::hmac::verify_hmac(
        alice_ks.as_bytes(),
        b"Server KC",
        alice_mac_s.as_bytes()
    ));
    assert_eq!(alice_mac_s.as_bytes(), alice_expected_mac_s.as_bytes());
    println!("Alcie: Valid MACs received.");

// Google ---------------------------------------------------------------------------------------------------

    assert!(crypto::hmac::verify_hmac(
        google_kc.as_bytes(),
        b"Client KC",
        google_mac_c.as_bytes()
    ));
    assert_eq!(google_mac_c.as_bytes(), google_expected_mac_c.as_bytes());
    println!("Google: Valid MACs received.");

// END ---------------------------------------------------------------------------------------------------

    println!("Done!");

}
