use crate::crypto;
use crate::crypto::hash2curve::hash2curve_demo;
use crate::crypto::hmac::{compute_hmac, verify_hmac};
use crate::crypto::key_schedule::{key_schedule_1, key_schedule_2, key_schedule_3};
use crate::crypto::participant::{Message, User, CA};
use aes_gcm::aead::OsRng;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::hash2curve::ExpandMsgXmd;
use elliptic_curve::{Field, PrimeField};
use image::EncodableLayout;
use k256::{ProjectivePoint, Scalar};
use kem::Decapsulate;
use ml_dsa::signature::Verifier;
use ml_dsa::{EncodedVerifyingKey, VerifyingKey};
use ml_dsa::{MlDsa65, Signature};
use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem768};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use std::io;
use std::net::TcpStream;
use rand_core::RngCore;

pub fn alice(ca: &mut CA, group_element: &mut ProjectivePoint) {
    let mut stream = TcpStream::connect("127.0.0.1:9000").unwrap();
    let mut aead_nonce: [u8; 12] = [0u8; 12];
    let ad = b"Alice,Google,";
    let _pw = b"a random password";
    let _username: &[u8] = b"alice";
    let g = group_element.clone();

// Register password and username for Google --------------------------------------------------------------------------------------

    {
        println!("Choose username: ");
        let mut username = String::new();
        io::stdin()
            .read_line(&mut username)
            .expect("Error reading username");
        println!("Choose password: ");
        let mut pw = String::new();
        io::stdin()
            .read_line(&mut pw)
            .expect("Error reading password");

        let username = username.as_bytes();
        let pw = pw.as_bytes();

        // Establish TLS connection
        let (_k1_c, _k1_s, _k2_c, _k2_s, k3_c, _k3_s) = pq_tls(&mut stream, ca, ad);

        // Send username and password to Google
        let mut msg = Vec::new();
        msg.extend_from_slice(b"Register;");
        msg.extend_from_slice(username);
        msg.extend_from_slice(b";");
        msg.extend_from_slice(pw);
        OsRng.fill_bytes(&mut aead_nonce);
        let cypher_text: Vec<u8> = match crypto::aead::encrypt(&k3_c, &aead_nonce, msg.as_bytes(), &ad.to_vec()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Encrypt error: {e}");
                return;
            }
        };
        let msg = Message::AeadCiphertext {
            nonce: aead_nonce,
            aead_payload: cypher_text,
        };
        User::send_bytes(&mut stream, &msg);
    }

// End of registration -----------------------------------------------------------------------------------------------------------
// Start login request -----------------------------------------------------------------------------------------------------------

    println!("Enter username: ");
    let mut username = String::new();
    io::stdin()
        .read_line(&mut username)
        .expect("Error reading username");
    println!("Enteralice password: ");
    let mut pw = String::new();
    io::stdin()
        .read_line(&mut pw)
        .expect("Error reading password");

    let username = username.as_bytes();
    let pw = pw.as_bytes();

    // ----------- OPRF stage -----------

    // Establish TLS connection
    let (_k1_c, _k1_s, _k2_c, _k2_s, k3_c, k3_s) = pq_tls(&mut stream, ca, ad);

    // Login request
    let a = Scalar::random(&mut OsRng);
    let h_pw: ProjectivePoint =
        hash2curve_demo::<k256::Secp256k1, ExpandMsgXmd<Sha3_256>>(pw)
            .expect("hash2curve_demo (k256 + SHA3-256) failed");

    let mut msg = Vec::new();
    msg.extend_from_slice(b"Login;");
    msg.extend_from_slice(username);
    msg.extend_from_slice(b";");
    msg.extend_from_slice((h_pw * a).to_bytes().as_bytes());
    OsRng.fill_bytes(&mut aead_nonce);
    let cypher_text: Vec<u8> = match crypto::aead::encrypt(&k3_c, &aead_nonce, msg.as_bytes(), &ad.to_vec()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Encrypt error: {e}");
            return;
        }
    };
    let msg = Message::AeadCiphertext {
        nonce: aead_nonce,
        aead_payload: cypher_text,
    };
    User::send_bytes(&mut stream, &msg);

    // Receive AEAD(k3_s, {{h_pw^as, enc_client_keys}}) message from Google
    let msg = User::recv_bytes(&mut stream);
    let (nonce, aead_payload) = match msg {
        Message::AeadCiphertext { nonce, aead_payload } => (nonce, aead_payload),
        _ => panic!("Unexpected message"),
    };
    let decrypted_msg: Vec<u8> = match crypto::aead::decrypt(&k3_s, &nonce, &aead_payload, &ad.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Decrypt error: {e}");
            return;
        }
    };
    if decrypted_msg.len() < 114 {
        eprintln!("Decrypt error: received malformed ratchet payload (len={})", decrypted_msg.len());
        return;
    }
    let (h_pw_as_bytes, rest_bytes) = decrypted_msg.split_at(33);
    let h_pw_as = ProjectivePoint::from_bytes(h_pw_as_bytes.into()).unwrap();
    let (enc_client_keys, enc_client_keys_nonce) = rest_bytes.split_at(114);

    // Decrypt enc_client_keys and verify correctness
    let h_pw_s = h_pw_as * a.invert().unwrap();
    let rw = Sha3_256::digest([pw.as_bytes(), h_pw_s.to_bytes().as_bytes()].concat());
    let (rw_key, _) = crypto::key_schedule::extract(None, rw.as_bytes());
    let client_key_info = crypto::aead::decrypt(rw_key.as_ref(), &enc_client_keys_nonce.try_into().unwrap(), enc_client_keys.as_bytes(), ad).unwrap();

    let alice_lsk_c_bytes: [u8; 32] = client_key_info[33..65].try_into().unwrap();
    let lsk_c: Scalar = Scalar::from_repr(alice_lsk_c_bytes.into()).expect("invalid Scalar encoding for alice_lsk_c");
    let _lpk_c: ProjectivePoint = ProjectivePoint::from_bytes(client_key_info[..33].try_into().unwrap()).unwrap();
    let lpk_s: ProjectivePoint = ProjectivePoint::from_bytes(client_key_info[65..98].try_into().unwrap()).unwrap();

    // ----------- AKE stage: 3DH -----------

    let x = Scalar::random(&mut OsRng);

    // Send ephemeral_pk to Google
    let mut msg = Vec::new();
    msg.extend_from_slice((g * x).to_bytes().as_bytes());
    OsRng.fill_bytes(&mut aead_nonce);
    let cypher_text: Vec<u8> = match crypto::aead::encrypt(&k3_c, &aead_nonce, msg.as_bytes(), &ad.to_vec()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Encrypt error: {e}");
            return;
        }
    };
    let msg = Message::AeadCiphertext {
        nonce: aead_nonce,
        aead_payload: cypher_text
    };
    User::send_bytes(&mut stream, &msg);

    // Receive ephemeral_pk from Google
    let msg = User::recv_bytes(&mut stream);
    let (nonce, aead_payload) = match msg {
        Message::AeadCiphertext { nonce, aead_payload } => (nonce, aead_payload),
        _ => panic!("Unexpected message"),
    };
    let decrypted_msg: Vec<u8> = match crypto::aead::decrypt(&k3_s, &nonce, &aead_payload, &ad.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Decrypt error: {e}");
            return;
        }
    };
    let large_y: ProjectivePoint = ProjectivePoint::from_bytes(decrypted_msg.as_slice().try_into().unwrap()).unwrap();

    // 3DH-KClient(𝑎, 𝑥, 𝐵, 𝑌)
    let mut key_input = Vec::new();
    key_input.extend_from_slice((lpk_s * x).to_bytes().as_bytes());
    key_input.extend_from_slice((large_y * x).to_bytes().as_bytes());
    key_input.extend_from_slice((large_y * lsk_c).to_bytes().as_bytes());
    let (sk, _) = crypto::key_schedule::extract(None, key_input.as_bytes());

    // ----------- Key Confirmation -----------

    // Calculate mac_c
    let (_, hk) = crypto::key_schedule::extract(None, sk.as_bytes());
    let combined_key = crypto::key_schedule::expand::<64>(&hk, b"Key Confirmation").unwrap();
    let (kc, ks) = combined_key.split_at(32);

    let mac_c = compute_hmac(kc.as_bytes(), b"Client KC");
    let expected_mac_s = compute_hmac(ks.as_bytes(), b"Server KC");

    // Send mac_c to Google
    OsRng.fill_bytes(&mut aead_nonce);
    let cypher_text: Vec<u8> = match crypto::aead::encrypt(&k3_c, &aead_nonce, mac_c.as_bytes(), &ad.to_vec()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Encrypt error: {e}");
            return;
        }
    };
    let msg = Message::AeadCiphertext {
        nonce: aead_nonce,
        aead_payload: cypher_text
    };
    User::send_bytes(&mut stream, &msg);

    // Receive mac_s from Google
    let msg = User::recv_bytes(&mut stream);
    let (nonce, aead_payload) = match msg {
        Message::AeadCiphertext { nonce, aead_payload } => (nonce, aead_payload),
        _ => panic!("Unexpected message"),
    };
    let mac_s: Vec<u8> = match crypto::aead::decrypt(&k3_s, &nonce, &aead_payload, &ad.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Decrypt error: {e}");
            return;
        }
    };

    // Verify MAC
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

    let mut rk_i = sk;

    loop {
        println!("Enter a message to send to Google: ");
        let mut message_from_user = String::new();
        io::stdin()
            .read_line(&mut message_from_user)
            .expect("Error reading message_from_user");
        let message_from_user = message_from_user.trim();


        let x_plus_1 = Scalar::random(&mut OsRng);
        let (rk_i_plus_1, ck_0) = kdf_rk(rk_i.as_bytes(), (large_y * x_plus_1).to_bytes().as_bytes());
        let (_ck_1, mk_1) = kdf_ck(ck_0.as_bytes());
        let c1: Vec<u8> = match crypto::aead::encrypt(&mk_1.try_into().unwrap(), &aead_nonce, message_from_user.as_bytes(), &ad.to_vec()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Encrypt error: {e}");
                return;
            }
        };

        // Send large_x_plus_one and c1 to Google
        let mut msg = Vec::new();
        msg.extend_from_slice(aead_nonce.as_bytes());
        msg.extend_from_slice((g * x_plus_1).to_bytes().as_bytes());
        msg.extend_from_slice(c1.as_bytes());
        OsRng.fill_bytes(&mut aead_nonce);
        let cypher_text: Vec<u8> = match crypto::aead::encrypt(&k3_c, &aead_nonce, msg.as_bytes(), &ad.to_vec()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Encrypt error: {e}");
                return;
            }
        };
        let msg = Message::AeadCiphertext {
            nonce: aead_nonce,
            aead_payload: cypher_text
        };
        User::send_bytes(&mut stream, &msg);

        // Receive large_x_plus_one and c1 from Alice
        let msg = User::recv_bytes(&mut stream);
        let (nonce, aead_payload) = match msg {
            Message::AeadCiphertext { nonce, aead_payload } => (nonce, aead_payload),
            _ => panic!("Unexpected message"),
        };
        let decrypted_msg: Vec<u8> = match crypto::aead::decrypt(&k3_s, &nonce, &aead_payload, &ad.as_ref()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Decrypt error: {e}");
                return;
            }
        };
        if decrypted_msg.len() < 45 {
            eprintln!("Decrypt error: received malformed ratchet payload (len={})", decrypted_msg.len());
            return;
        }
        let (nonce_and_large_y_plus_one_as_bytes, c1) = decrypted_msg.split_at(45);
        let (nonce, large_y_plus_one_as_bytes) = nonce_and_large_y_plus_one_as_bytes.split_at(12);
        let large_y_plus_one = ProjectivePoint::from_bytes(large_y_plus_one_as_bytes.into()).unwrap();


        // Recover the chains
        let (rk_i_plus_2, ck_0) = kdf_rk(rk_i_plus_1.as_bytes(), (large_y_plus_one * x_plus_1).to_bytes().as_bytes());
        let (_ck_1, mk_1) = kdf_ck(ck_0.as_bytes());

        let message_from_server: Vec<u8> = match crypto::aead::decrypt(&mk_1.try_into().unwrap(), &nonce.try_into().unwrap(), &c1, &ad.as_ref()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Decrypt error: {e}");
                return;
            }
        };

        let message_text = String::from_utf8_lossy(&message_from_server);
        println!("Received message from Google: {}", message_text);

        rk_i = rk_i_plus_2.into();
    }
}

fn kdf_ck(ck_i: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let ck_i_plus_1 = compute_hmac(ck_i.as_bytes(), b"ChainKey");
    let mk_i = compute_hmac(ck_i.as_bytes(), b"MessageKey");

    (ck_i_plus_1, mk_i)
}

fn kdf_rk(rk_i: &[u8], dh: &[u8]) -> ([u8; 32], [u8; 32]) {
    let (_, hk) = crypto::key_schedule::extract(Some(rk_i), dh);
    let rk_i_plus_1 = crypto::key_schedule::expand::<32>(&hk, b"RootKey").unwrap();
    let ck_i = crypto::key_schedule::expand::<32>(&hk, b"ChainKey").unwrap();

    (rk_i_plus_1, ck_i)
}

fn pq_tls(
    mut stream: &mut TcpStream,
    ca: &mut CA,
    ad: &[u8; 13]
) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32]) {

    let mut nonce_c: [u8; 8] = [0u8; 8];
    OsRng.fill_bytes(&mut nonce_c);
    let mut aead_nonce: [u8; 12] = [0u8; 12];
    let (dk, ek) = MlKem768::generate(&mut OsRng);

    // Send nonce_c, ek to Google
    let msg = Message::PqtlsClientHello {
        nonce_c: nonce_c.to_vec(),
        ek: ek.as_bytes().to_vec(),
    };
    User::send_bytes(&mut stream, &msg);

    // Receive PqtlsServerHello from Alive
    let msg = User::recv_bytes(&mut stream);
    let (nonce_s, ct_bytes, verifying_key_bytes) = match msg {
        Message::PqtlsServerHello { nonce_s, ct, verifying_key } => (nonce_s, ct, verifying_key),
        _ => panic!("Unexpected message"),
    };
    let verifying_key = VerifyingKey::<MlDsa65>::decode(
        &EncodedVerifyingKey::<MlDsa65>::try_from(verifying_key_bytes.as_slice())
            .expect("Invalid verifying key bytes"),
    );
    let ct = Ciphertext::<MlKem768>::try_from(ct_bytes.as_slice())
        .expect("ungültiger Ciphertext");

    // Calculate shared key and K1_c, K1_s, K2_c, K2_s
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
    let msg = User::recv_bytes(&mut stream);
    let (nonce, aead_payload) = match msg {
        Message::AeadCiphertext { nonce, aead_payload } => (nonce, aead_payload),
        _ => panic!("Unexpected message"),
    };
    let decrypted_msg: Vec<u8> = match crypto::aead::decrypt(&k1_s, &nonce, &aead_payload, &ad.to_vec()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Decrypt error: {e}");
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
    OsRng.fill_bytes(&mut aead_nonce);
    let cypher_text: Vec<u8> = match crypto::aead::encrypt(&k1_c, &aead_nonce, mac_c.as_bytes(), &ad.to_vec()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Encrypt error: {e}");
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