mod tests {
    use crate::crypto::hash2curve::hash2curve_demo;
    use crate::crypto::participant;
    use crate::crypto::participant::{DatabaseContent, Message, User, CA};
    use crate::{alice, crypto, google};
    use elliptic_curve::hash2curve::ExpandMsgXmd;
    use image::EncodableLayout;
    use k256::ProjectivePoint;
    use rand::RngCore;
    use sha3::Sha3_256;
    use std::collections::HashMap;
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn test_test() {
        assert_eq!(1, 1);
    }

    #[test]
    fn test_register_and_login() {

        // initialize and start server
        let mut ca = participant::CA::new();
        let mut ca_clone = ca.clone();

        let len = 16;
        let mut random_bytes = vec![0u8; len];
        rand::rng().fill_bytes(&mut random_bytes);
        let mut g: ProjectivePoint =
            hash2curve_demo::<k256::Secp256k1, ExpandMsgXmd<Sha3_256>>(random_bytes.as_bytes())
                .expect("hash2curve_demo (k256 + SHA3-256) failed");

        let handle = std::thread::spawn(move || {
            sim_google(&mut ca_clone, &mut g);
        });

        std::thread::sleep(std::time::Duration::from_millis(500));

        let mut stream = TcpStream::connect("127.0.0.1:9000").unwrap();
        let mut aead_nonce: [u8; 12] = [0u8; 12];
        let ad = b"Alice,Google,";
        let username = "alice";
        let pw = "12345";

        assert!(!alice::register(&mut ca, &mut stream, &mut aead_nonce, &ad, &username, &pw));
        assert!(!alice::login(&mut ca, &mut stream, &mut aead_nonce, &ad, g, &username, &pw));

        handle.join().unwrap();
    }

    fn sim_google(ca: &mut CA, g: &mut ProjectivePoint) {
        let listener = TcpListener::bind("127.0.0.1:9000").unwrap();
        let (mut stream, _) = listener.accept().unwrap();

        let mut aead_nonce: [u8; 12] = [0u8; 12];
        let ad = b"Alice,Google,";
        let mut database: HashMap<Vec<u8>, DatabaseContent> = HashMap::new();

        let (_k1_c, _k1_s, _k2_c, _k2_s, k3_c, _k3_s) = google::pq_tls(&mut stream, ca, ad);

        let msg = User::recv_bytes(&mut stream);
        let (nonce, aead_payload) = match msg {
            Message::AeadCiphertext { nonce, aead_payload } => (nonce, aead_payload),
            _ => panic!("Google: Unexpected message"),
        };
        let decrypted_msg: Vec<u8> = match crypto::aead::decrypt(&k3_c, &nonce, &aead_payload, &ad.as_ref()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Google: Decrypt error: {e}");
                return;
            }
        };
        let mut parts = decrypted_msg.splitn(3, |&b| b == b';');
        let _action = parts.next().unwrap_or(&[]);
        let mut username = parts.next().unwrap_or(&[]);
        let mut content = parts.next().unwrap_or(&[]);

        assert!(!google::register(
            &mut aead_nonce,
            &ad,
            &mut database,
            *g,
            &mut username,
            &mut content
        ));

        let (_k1_c, _k1_s, _k2_c, _k2_s, k3_c, k3_s) = google::pq_tls(&mut stream, ca, ad);

        let msg = User::recv_bytes(&mut stream);
        let (nonce, aead_payload) = match msg {
            Message::AeadCiphertext { nonce, aead_payload } => (nonce, aead_payload),
            _ => panic!("Google: Unexpected message"),
        };
        let decrypted_msg: Vec<u8> = match crypto::aead::decrypt(&k3_c, &nonce, &aead_payload, &ad.as_ref()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Google: Decrypt error: {e}");
                return;
            }
        };
        let mut parts = decrypted_msg.splitn(3, |&b| b == b';');
        let _action = parts.next().unwrap_or(&[]);
        let mut username = parts.next().unwrap_or(&[]);
        let mut content = parts.next().unwrap_or(&[]);

        assert!(!google::login(
            k3_c,
            k3_s,
            &mut stream,
            &mut aead_nonce,
            &ad,
            &mut database,
            *g,
            &mut username,
            &mut content
        ));
    }
}