use k256::elliptic_curve::sec1::ToEncodedPoint;
use kem::{Decapsulate, Encapsulate};
use ml_kem::{KemCore, MlKem768};
use crate::ecdsa::sign;
use crate::graph::render_graph;
use crate::hmac::compute_hmac;
use crate::key_schedule::{key_schedule_1, key_schedule_2, key_schedule_3, sha256_digest};
use crate::participant::{ContentValue, User};
mod participant;
mod graph;
mod key_schedule;
mod ecdsa;
mod hmac;
/* TODO
 * pk and sk don't correctly get used, because they are from ecdsa while shared secret is from ml_kem
 * send ct fails because the type "EncodedCiphertext" is private
 * k3 is missing
 */
fn main() {
    let mut graph = graph::Graph::new();
    let mut rng = rand::thread_rng();

    let mut ca = participant::CA::new();
    let mut alice = User::new("Alice".into(), rng.clone(), &mut graph);
    let mut google = User::new("Google".into(), rng.clone(), &mut graph);

// Alice ---------------------------------------------------------------------------------------------------
    alice.send_message(
        "X".into(),
        ContentValue::PublicKey(alice.public_key()),
        &mut google,
        &mut graph,
    );

// Google ---------------------------------------------------------------------------------------------------
    google.send_message(
        "Y".into(),
        ContentValue::PublicKey(google.public_key()),
        &mut alice,
        &mut graph,
    );

// Alice ---------------------------------------------------------------------------------------------------
    let (dk, ek) = MlKem768::generate(&mut rng);
    alice.send_messages(
        vec!["nonce_c".to_string(), "ek".to_string()],
        vec![ContentValue::Nonce(alice.nonce()), ContentValue::EncapsulationKey(ek)],
        &mut google,
        &mut graph,
    );

// Google ---------------------------------------------------------------------------------------------------
    let mut alice_nonce = match google.get("nonce_c") {
        ContentValue::Nonce(r) => r,
        _ => panic!("nonce_c ist kein Nonce"),
    };
    let ek = match google.get("ek") {
        ContentValue::EncapsulationKey(k) => k,
        _ => panic!("ek fehlt"),
    };
    let alice_pk = match google.get("X") {
        ContentValue::PublicKey(k) => k,
        _ => panic!("Y fehlt"),
    };
    let (ct, k_send) = ek.encapsulate(&mut rng).unwrap();

    // Calculate K1_c, K1_s, K2_c, K2_s
    let (google_k1_c, google_k1_s) = key_schedule_1(k_send.as_ref()).unwrap();
    let (google_k2_c, google_k2_s) = key_schedule_2(
        alice_nonce.as_mut(),
        &alice_pk.to_encoded_point(false).as_bytes(),
        google.nonce().as_mut(),
        &google.public_key().to_encoded_point(false).as_bytes(),
        k_send.as_ref(),
    ).unwrap();

    // Get certificate for google's public key
    let (cert_pk_r, cert_pk_s) = ca.generate_certificate(&google.public_key().to_encoded_point(false).as_bytes()).unwrap();
    let mut cert_pk = Vec::new();
    cert_pk.extend_from_slice(cert_pk_r.as_ref());
    cert_pk.extend_from_slice(cert_pk_s.as_ref());

    // Calculate google's signature
    let mut digest_input = Vec::new();
    digest_input.extend_from_slice(alice_nonce.as_mut());
    digest_input.extend_from_slice(&alice_pk.to_encoded_point(false).as_bytes());
    digest_input.extend_from_slice(google.nonce().as_mut());
    digest_input.extend_from_slice(&google.public_key().to_encoded_point(false).as_bytes());
    digest_input.extend_from_slice(cert_pk.as_ref());

    let (google_sign_r, google_sign_s) = sign(
        google.secret_key().as_ref(),
        &sha256_digest(&digest_input)
    ).unwrap();
    let mut google_sign = Vec::new();
    google_sign.extend_from_slice(google_sign_r.as_ref());
    google_sign.extend_from_slice(google_sign_s.as_ref());


    // Calculate google's MAC tag
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(alice_nonce.as_mut());
    mac_input.extend_from_slice(&alice_pk.to_encoded_point(false).as_bytes());
    mac_input.extend_from_slice(google.nonce().as_mut());
    mac_input.extend_from_slice(&google.public_key().to_encoded_point(false).as_bytes());
    mac_input.extend_from_slice(google_sign.as_ref());
    mac_input.extend_from_slice(cert_pk.as_ref());
    mac_input.extend_from_slice(b"ServerMAC");

    let mac_s = compute_hmac(&google_k2_s, &sha256_digest(&mac_input));

    // Calculate K3_c, K3_s
    let (google_k3_c, google_k3_s) = key_schedule_3(
        alice_nonce.as_mut(),
        &alice_pk.to_encoded_point(false).as_bytes(),
        google.nonce().as_mut(),
        &google.public_key().to_encoded_point(false).as_bytes(),
        k_send.as_ref(),
        google_sign.as_ref(),
        cert_pk.as_ref(),
        mac_s.as_ref(),
    ).unwrap();

    // google.send_messages(
    //     vec!["nonce_s".to_string(), "ct".to_string()],
    //     vec![ContentValue::Nonce(google.nonce()), ContentValue::EncodedCiphertext(ct)],
    //     &mut alice,
    //     &mut graph,
    // );
    google.send_message(
        "nonce_s".to_string(),
        ContentValue::Nonce(google.nonce()),
        &mut alice,
        &mut graph,
    );

// Alice ---------------------------------------------------------------------------------------------------

    // let ct = match google.get("ct") {
    //     ContentValue::EncodedCiphertext(k) => k,
    //     _ => panic!("ct fehlt"),
    // };
    let mut google_nonce = match alice.get("nonce_s") {
        ContentValue::Nonce(r) => r,
        _ => panic!("nonce_s ist kein Nonce"),
    };
    let google_pk = match alice.get("Y") {
        ContentValue::PublicKey(k) => k,
        _ => panic!("Y fehlt"),
    };
    let k_recv = dk.decapsulate(&ct).unwrap();
    let (alice_k1_c, alice_k1_s) = key_schedule_1(k_recv.as_ref()).unwrap();
    let (alice_k2_c, alice_k2_s) = key_schedule_2(
        alice.nonce().as_mut(),
        &alice.public_key().to_encoded_point(false).as_bytes(),
        google_nonce.as_mut(),
        &google_pk.to_encoded_point(false).as_bytes(),
        k_recv.as_ref(),
    ).unwrap();

    assert_eq!(alice_k1_c, google_k1_c);
    assert_eq!(alice_k1_s, google_k1_s);
    assert_eq!(alice_k2_c, google_k2_c);
    assert_eq!(alice_k2_s, google_k2_s);

    render_graph(&graph, "messages.png");
}