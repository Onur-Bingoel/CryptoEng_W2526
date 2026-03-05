use crate::crypto;
use crate::crypto::hash2curve::hash2curve_demo;
use crate::crypto::hmac::{compute_hmac, verify_hmac};
use crate::crypto::key_schedule::{key_schedule_1, key_schedule_2, key_schedule_3};
use crate::crypto::participant::{DatabaseContent, Message, User, CA};
use aes_gcm::aead::OsRng;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::hash2curve::ExpandMsgXmd;
use elliptic_curve::Field;
use hmac::digest::{Digest, Output};
use image::EncodableLayout;
use k256::{ProjectivePoint, Scalar};
use kem::Encapsulate;
use ml_dsa::signature::Signer;
use ml_dsa::{KeyGen, MlDsa65, Seed};
use ml_kem::kem::EncapsulationKey;
use ml_kem::{EncodedSizeUser, MlKem768Params};
use rand_core::RngCore;
use sha2::Sha256;
use sha3::Sha3_256;
use std::collections::HashMap;
use std::net::{TcpListener, TcpStream};
use std::panic;
use std::sync::atomic::{AtomicBool, Ordering};

static RECEIVED_RESET: AtomicBool = AtomicBool::new(false);

pub fn google(ca: &mut CA, group_element: &mut ProjectivePoint) {
    let listener = TcpListener::bind("127.0.0.1:9000").unwrap();
    let (mut stream, _) = listener.accept().unwrap();
    loop {
        panic::set_hook(Box::new(|_| {
        }));
        match panic::catch_unwind(panic::AssertUnwindSafe(|| {
            match google_inner(ca, group_element, &mut stream) {
                _ => panic!("Google: Error in google_inner"),
            }
        })) {
            _ => {
                if !RECEIVED_RESET.load(Ordering::Relaxed) {
                    // println!("Google: An error occurred, resetting connection...");
                    User::send_bytes(&mut stream, &Message::Reset {});
                };
                RECEIVED_RESET.store(false, Ordering::Relaxed);
            }
        }
    }
}

pub fn google_inner(ca: &mut CA, group_element: &mut ProjectivePoint, mut stream: &mut TcpStream) {
    let mut aead_nonce: [u8; 12] = [0u8; 12];
    let ad = b"Alice,Google,";
    let mut database: HashMap<Vec<u8>, DatabaseContent> = HashMap::new();
    let g = group_element.clone();

    loop {
        // Establish TLS connection
        // println!("Google: Establishing TLS connection");
        let (_k1_c, _k1_s, _k2_c, _k2_s, k3_c, k3_s) = pq_tls(&mut stream, ca, ad);
        // println!("Google: TLS connection established.");

        // Receive message from Alice
        // println!("Google: Waiting for message from Alice");
        let msg = User::recv_bytes(&mut stream);
        let (nonce, aead_payload) = match msg {
            Message::AeadCiphertext { nonce, aead_payload } => (nonce, aead_payload),
            _ => {
                match msg {
                    Message::Reset {} => (),
                    _ => {
                        eprintln!("Google: Unexpected message");
                        return;
                    }
                }
                RECEIVED_RESET.store(true, Ordering::Relaxed);
                panic!("Google: Unexpected message")
            },
        };
        let decrypted_msg: Vec<u8> = match crypto::aead::decrypt(&k3_c, &nonce, &aead_payload, &ad.as_ref()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Google: Decrypt error: {e}");
                return;
            }
        };
        let mut parts = decrypted_msg.splitn(3, |&b| b == b';');
        let action = parts.next().unwrap_or(&[]);
        let action_text = String::from_utf8_lossy(&action);
        let mut username = parts.next().unwrap_or(&[]);
        let mut content = parts.next().unwrap_or(&[]);

        if action == b"Register" {
            if register(
                &mut aead_nonce,
                &ad,
                &mut database,
                g,
                &mut username,
                &mut content
            ) {
                eprintln!("Google: Register error");
                return; 
            }
        } else if action == b"Login" {
            if login(
                k3_c,
                k3_s,
                &mut stream,
                &mut aead_nonce,
                &ad,
                &mut database,
                g,
                &mut username,
                &mut content
            ) {
                eprintln!("Google: Login error");
                return;
            }
        } else {
            eprintln!("Google: Invalid action: {action_text}");
            return;
        }

    }
}

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
    // println!("Google: OPRF stage");

    let h_pw_a = ProjectivePoint::from_bytes(content.into()).unwrap();

    // Load saved data from database
    // println!("Google: Loading saved data for user: {}", String::from_utf8_lossy(username));
    let saved_data = match database.get(username) {
        Some(data) => data,
        None => {
            eprintln!("Google: Username not found");
            return true;
        }
    };

    // Send AEAD(k3_s, {{h_pw^as, enc_client_keys}}) message from Google to Alice
    // println!("Google: Sending AEAD(k3_s, {{h_pw^as, enc_client_keys}}) message to Alice");
    let mut msg = Vec::new();
    msg.extend_from_slice((h_pw_a * saved_data.salt).to_bytes().as_bytes());
    msg.extend_from_slice(saved_data.enc_client_keys.as_slice());
    msg.extend_from_slice(saved_data.aead_nonce.as_bytes());
    OsRng.fill_bytes(aead_nonce);
    let cypher_text: Vec<u8> = match crypto::aead::encrypt(&k3_s, &aead_nonce, msg.as_bytes(), &ad.to_vec()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Google: Encrypt error: {e}");
            return true;
        }
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
    // println!("Google: AKE stage");

    let y = Scalar::random(&mut OsRng);

    // Receive ephemeral_pk key from Alice
    // println!("Google: Waiting for ephemeral_pk from Alice");
    let msg = User::recv_bytes(&mut stream);
    let (nonce, aead_payload) = match msg {
        Message::AeadCiphertext { nonce, aead_payload } => (nonce, aead_payload),
        _ => {
            match msg {
                Message::Reset {} => (),
                _ => {
                    eprintln!("Google: Unexpected message");
                    return true;
                }
            }
            RECEIVED_RESET.store(true, Ordering::Relaxed);
            panic!("Google: Unexpected message")
        },
    };
    let decrypted_msg: Vec<u8> = match crypto::aead::decrypt(&k3_c, &nonce, &aead_payload, &ad.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Google: Decrypt error: {e}");
            return true;
        }
    };
    let large_x: ProjectivePoint = ProjectivePoint::from_bytes(decrypted_msg.as_slice().try_into().unwrap()).unwrap();

    // Send ephemeral_pk key to Alice
    // println!("Google: Sending ephemeral_pk key to Alice");
    let mut msg = Vec::new();
    msg.extend_from_slice((g * y).to_bytes().as_bytes());
    OsRng.fill_bytes(aead_nonce);
    let cypher_text: Vec<u8> = match crypto::aead::encrypt(&k3_s, &aead_nonce, msg.as_bytes(), &ad.to_vec()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Google: Encrypt error: {e}");
            return true;
        }
    };
    let msg = Message::AeadCiphertext {
        nonce: *aead_nonce,
        aead_payload: cypher_text
    };
    User::send_bytes(&mut stream, &msg);

    // 3DH-KServer (𝑏, 𝑦, 𝐴, 𝑋)
    // println!("Google: Calculating SK");
    let mut key_input = Vec::new();
    key_input.extend_from_slice((large_x * lsk_s).to_bytes().as_bytes());
    key_input.extend_from_slice((large_x * y).to_bytes().as_bytes());
    key_input.extend_from_slice((lpk_c * y).to_bytes().as_bytes());
    let (sk, _) = crypto::key_schedule::extract(None, key_input.as_bytes());

    // ----------- Key Confirmation -----------
    // println!("Google: Key Confirmation stage");

    // Calculate mac_s
    // println!("Google: Calculating mac_s");
    let (_, hk) = crypto::key_schedule::extract(None, sk.as_bytes());
    let combined_key = crypto::key_schedule::expand::<64>(&hk, b"Key Confirmation").unwrap();
    let (kc, ks) = combined_key.split_at(32);

    let mac_s = compute_hmac(ks.as_bytes(), b"Server KC");
    let expected_mac_c = compute_hmac(kc.as_bytes(), b"Client KC");

    // Receive mac_c from Alice
    // println!("Google: Waiting for mac_c from Alice");
    let msg = User::recv_bytes(&mut stream);
    let (nonce, aead_payload) = match msg {
        Message::AeadCiphertext { nonce, aead_payload } => (nonce, aead_payload),
        _ => {
            match msg {
                Message::Reset {} => (),
                _ => {
                    eprintln!("Google: Unexpected message");
                    return true;
                }
            }
            RECEIVED_RESET.store(true, Ordering::Relaxed);
            panic!("Google: Unexpected message")
        },
    };
    let mac_c: Vec<u8> = match crypto::aead::decrypt(&k3_c, &nonce, &aead_payload, &ad.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Google: Decrypt error: {e}");
            return true;
        }
    };

    // Send mac_s to Alice
    // println!("Google: Sending mac_s to Alice");
    OsRng.fill_bytes(aead_nonce);
    let cypher_text: Vec<u8> = match crypto::aead::encrypt(&k3_s, &aead_nonce, mac_s.as_bytes(), &ad.to_vec()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Google: Encrypt error: {e}");
            return true;
        }
    };
    let msg = Message::AeadCiphertext {
        nonce: *aead_nonce,
        aead_payload: cypher_text
    };
    User::send_bytes(&mut stream, &msg);

    // Verify mac_c
    // println!("Google: Verifying mac_c");
    assert!(verify_hmac(
        kc.as_bytes(),
        b"Client KC",
        mac_c.as_bytes()
    ));
    assert_eq!(mac_c.as_bytes(), expected_mac_c.as_bytes());
    // println!("Google: Valid MACs received.");

    // End of login -----------------------------------------------------------------------------------------------------------
    // Start communication -----------------------------------------------------------------------------------------------------------

    // ----------- Double Ratchet -----------
    // println!("Google: Double Ratchet stage");

    let mut rk_i = sk;
    let mut _large_x_i = large_x;
    let mut y_i = y;

    #[cfg(not(test))]
    loop {
        let (large_x_plus_one, y_i_plus_1, rk_i_plus_2, _) = match inner_double_ratchet(&k3_c, &k3_s, &mut stream, aead_nonce, &ad, g, rk_i, y_i) {
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

pub(crate) fn inner_double_ratchet(k3_c: &[u8; 32], k3_s: &[u8; 32], mut stream: &mut &mut TcpStream, aead_nonce: &mut [u8; 12], ad: &&&[u8; 13], g: ProjectivePoint, mut rk_i: Output<Sha256>, mut y_i: Scalar) -> Result<(ProjectivePoint, Scalar, [u8; 32], String), bool> {
    // Receive large_x_i_plus_one and c1 from Alice
    // println!("Google: Waiting for X_i+1 and c1 from Alice");
    let msg = User::recv_bytes(&mut stream);
    let (nonce, aead_payload) = match msg {
        Message::AeadCiphertext { nonce, aead_payload } => (nonce, aead_payload),
        _ => {
            match msg {
                Message::Reset {} => (),
                _ => {
                    eprintln!("Google: Unexpected message");
                    return Err(true);
                }
            }
            RECEIVED_RESET.store(true, Ordering::Relaxed);
            panic!("Google: Unexpected message")
        },
    };
    let decrypted_msg: Vec<u8> = match crypto::aead::decrypt(&k3_c, &nonce, &aead_payload, &ad.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Google: Decrypt error: {e}");
            return Err(true);
        }
    };
    if decrypted_msg.len() < 45 {
        eprintln!("Google: Decrypt error: received malformed ratchet payload (len={})", decrypted_msg.len());
        return Err(true);
    }
    let (nonce_and_large_x_plus_one_as_bytes, c1) = decrypted_msg.split_at(45);
    let (nonce, large_x_plus_one_as_bytes) = nonce_and_large_x_plus_one_as_bytes.split_at(12);
    let large_x_plus_one = ProjectivePoint::from_bytes(large_x_plus_one_as_bytes.into()).unwrap();

    // Recover the chains
    // println!("Google: Recovering chains");
    let (rk_i_plus_1, ck_0) = kdf_rk(rk_i.as_bytes(), (large_x_plus_one * y_i).to_bytes().as_bytes());
    let (ck_1, mk_1) = kdf_ck(ck_0.as_bytes());

    let message_from_user: Vec<u8> = match crypto::aead::decrypt(&mk_1.try_into().unwrap(), &nonce.try_into().unwrap(), &c1, &ad.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Google: Decrypt error: {e}");
            return Err(true);
        }
    };

    // Echo message_from_user
    let message_text = String::from_utf8_lossy(&message_from_user);
    let message_from_server = format!("Echo => {}", message_text);

    // Can be used for multiple messages
    let (_ck_2, _mk_2) = kdf_ck(ck_1.as_bytes());


    // Encrypt message_from_server with DH Ratchet and Sym Ratchet
    // println!("Google: Encrypting message_from_server with DH Ratchet and Sym Ratchet");
    let y_i_plus_1 = Scalar::random(&mut OsRng);
    let (rk_i_plus_2, ck_0) = kdf_rk(rk_i_plus_1.as_bytes(), (large_x_plus_one * y_i_plus_1).to_bytes().as_bytes());
    let (ck_1, mk_1) = kdf_ck(ck_0.as_bytes());
    OsRng.fill_bytes(aead_nonce);
    let c1: Vec<u8> = match crypto::aead::encrypt(&mk_1.try_into().unwrap(), &aead_nonce, message_from_server.as_bytes(), &ad.to_vec()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Google: Encrypt error: {e}");
            return Err(true);
        }
    };

    // Send large_y_i_plus_one and c1 to Alice
    // println!("Google: Sending Y_i+1 and c1 to Alice");
    let mut msg = Vec::new();
    msg.extend_from_slice(aead_nonce.as_bytes());
    msg.extend_from_slice((g * y_i_plus_1).to_bytes().as_bytes());
    msg.extend_from_slice(c1.as_bytes());
    OsRng.fill_bytes(aead_nonce);
    let cypher_text: Vec<u8> = match crypto::aead::encrypt(&k3_s, &aead_nonce, msg.as_bytes(), &ad.to_vec()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Google: Encrypt error: {e}");
            return Err(true);
        }
    };
    let msg = Message::AeadCiphertext {
        nonce: *aead_nonce,
        aead_payload: cypher_text
    };
    User::send_bytes(&mut stream, &msg);

    // Can be used for multiple messages
    let (_ck_2, _mk_2) = kdf_ck(ck_1.as_bytes());
    Ok((large_x_plus_one, y_i_plus_1, rk_i_plus_2, format!("{}", message_text)))
}

pub(crate) fn register(
    aead_nonce:
    &mut [u8; 12],
    ad: &&[u8; 13],
    database: &mut HashMap<Vec<u8>, DatabaseContent>,
    g: ProjectivePoint,
    username: &[u8],
    password: &[u8]
) -> bool {
    {

        // Calculate client_key_info and save in database
        // println!("Google: Registering user: {}", String::from_utf8_lossy(username));
        let s = Scalar::random(&mut OsRng);
        let h_pw: ProjectivePoint =
            hash2curve_demo::<k256::Secp256k1, ExpandMsgXmd<Sha3_256>>(password)
                .expect("hash2curve_demo (k256 + SHA3-256) failed");

        let rw = Sha3_256::digest([password.as_bytes(), (h_pw * s).to_bytes().as_bytes()].concat());
        let (rw_key, _) = crypto::key_schedule::extract(None, rw.as_bytes());
        let lsk_s = Scalar::random(&mut OsRng);
        let lpk_s: ProjectivePoint = g * lsk_s;

        let lsk_c = Scalar::random(&mut OsRng);
        let lpk_c: ProjectivePoint = g * lsk_c;

        let mut client_key_info = Vec::new();
        client_key_info.extend_from_slice(&lpk_c.to_bytes());
        client_key_info.extend_from_slice(&lsk_c.to_bytes());
        client_key_info.extend_from_slice(&lpk_s.to_bytes());

        OsRng.fill_bytes(aead_nonce);
        let enc_client_keys = crypto::aead::encrypt(
            rw_key.as_ref(),
            &aead_nonce,
            client_key_info.as_bytes(),
            ad.as_ref(),
        ).unwrap();

        database.insert(username.to_vec(), DatabaseContent {
            salt: s,
            lpk_c,
            lpk_s,
            lsk_s,
            aead_nonce: *aead_nonce,
            enc_client_keys,
        });
        // println!("Google: Client keys saved.");
    };
    false
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

pub(crate) fn pq_tls(
    mut stream: &mut TcpStream,
    ca: &mut CA,
    ad: &[u8; 13]
) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32]) {

    let mut nonce_s: [u8; 8] = [0u8; 8];
    OsRng.fill_bytes(&mut nonce_s);
    let mut aead_nonce: [u8; 12] = [0u8; 12];

    // Receive PqtlsClientHello from Alive
    // println!("Google: Waiting for PqtlsClientHello from Alice");
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
            RECEIVED_RESET.store(true, Ordering::Relaxed);
            panic!("Google: Unexpected message")
        },
    };
    const EK768_LEN: usize = 1184;
    let ek_arr: [u8; EK768_LEN] = ek_bytes.as_slice().try_into()
        .expect("ungültige EncapsulationKey-Bytes (falsche Länge)");
    let ek = EncapsulationKey::<MlKem768Params>::from_bytes((&ek_arr).as_ref());

    // Generate key pair and calculate shared key and ciphertext
    // println!("Google: Generating key pair and calculating shared key and ciphertext");
    let key_pair = MlDsa65::from_seed(&Seed::default());
    let (ct, shared_key) = ek.encapsulate(&mut OsRng).unwrap();

    // Calculate K1_c, K1_s, K2_c, K2_s
    // println!("Google: Calculating K1_c, K1_s, K2_c, K2_s");
    let (k1_c, k1_s) = key_schedule_1(shared_key.as_bytes());
    let (k2_c, k2_s) = key_schedule_2(
        nonce_c.clone().as_bytes(),
        ek.as_bytes().as_bytes(),
        nonce_s.clone().as_bytes(),
        key_pair.verifying_key().encode().as_bytes(),
        shared_key.as_bytes(),
    );

    // Get certificate for google's public key
    // println!("Google: Getting certificate for google's public key");
    let cert = ca.generate_certificate(key_pair.verifying_key().encode().as_bytes());

    // Calculate google's signature
    // println!("Google: Calculating google's signature");
    let mut sign_digest_input = Vec::new();
    sign_digest_input.extend_from_slice(nonce_c.clone().as_bytes());
    sign_digest_input.extend_from_slice(ek.as_bytes().as_bytes());
    sign_digest_input.extend_from_slice(nonce_s.as_bytes());
    sign_digest_input.extend_from_slice(key_pair.verifying_key().encode().as_bytes());
    sign_digest_input.extend_from_slice(cert.encode().as_bytes());

    let google_sign = key_pair.signing_key().sign(&Sha256::digest(&sign_digest_input));

    // Calculate google's MAC tag
    // println!("Google: Calculating google's MAC tag");
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
    // println!("Google: Calculating K3_c, K3_s");
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
    // println!("Google: Sending nonce_s, ct, verifying_key from Google to Alice");
    let msg = Message::PqtlsServerHello {
        nonce_s: nonce_s.to_vec(),
        ct: ct.as_bytes().to_vec(),
        verifying_key: key_pair.verifying_key().encode().as_bytes().to_vec(),
    };
    User::send_bytes(&mut stream, &msg);

    // Send AEAD(k1_s, {{cert , google_sign, mac_s}}) message from Google to Alice
    // println!("Google: Sending AEAD(k1_s, {{cert , google_sign, mac_s}}) message from Google to Alice");
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
    // println!("Google: Receiving and decrypting the AEAD message");
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
            RECEIVED_RESET.store(true, Ordering::Relaxed);
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
    // println!("Google: Verifying the MAC tag from Alice");
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
