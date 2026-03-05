mod tests {
    use crate::client::alice;
    use crate::server::google;
    use crate::crypto::participant::{DatabaseContent, Message, User, CA};
    use crate::{crypto};
    use elliptic_curve::{Field, Group};
    use hmac::digest::Output;
    use image::EncodableLayout;
    use k256::{ProjectivePoint, Scalar};
    use rand_core::OsRng;
    use rand_core::RngCore;
    use sha2::Sha256;
    use std::collections::HashMap;
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn test_register_and_login() {
        let mut ca = CA::new();
        let mut ca_clone = ca.clone();
        let mut g: ProjectivePoint = ProjectivePoint::random(&mut OsRng);

        let handle = std::thread::spawn(move || {
            sim_google(&mut ca_clone, &mut g);
        });

        std::thread::sleep(std::time::Duration::from_millis(500));

        let mut stream = TcpStream::connect("127.0.0.1:9001").unwrap();
        let mut aead_nonce: [u8; 12] = [0u8; 12];
        
        let ad = b"Alice,Google,";
        let username = "alice";
        let pw = "12345";

        assert!(!alice::register(&mut ca, &mut stream, &mut aead_nonce, &ad, &username, &pw));
        assert!(!alice::login(&mut ca, &mut stream, &mut aead_nonce, &ad, g, &username, &pw));

        drop(stream);

        handle.join().unwrap();

        println!("Test register_and_login finished.\n\n");
    }

    fn sim_google(ca: &mut CA, g: &mut ProjectivePoint) {
        let listener = TcpListener::bind("127.0.0.1:9001").unwrap();
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

        drop(stream);
        drop(listener);
    }
    
    #[test]
    fn test_double_ratchet() {
        let ad = b"Alice,Google,";
        let mut k3_c = [0u8; 32];
        OsRng.fill_bytes(&mut k3_c);
        let mut k3_s = [0u8; 32];
        OsRng.fill_bytes(&mut k3_s);
        let mut g: ProjectivePoint = ProjectivePoint::random(&mut OsRng);
        
        let len = 16;
        let mut random_bytes = vec![0u8; len];
        OsRng.fill_bytes(&mut random_bytes);
        
        let (mut sk, _) = crypto::key_schedule::extract(None, random_bytes.as_bytes());
        let mut x_i = Scalar::random(&mut OsRng);
        let mut y_i = Scalar::random(&mut OsRng);
        let message_1_from_user = "Hello, world!";
        let message_2_from_user = "How are you?";
        
        let handle = std::thread::spawn(move || {
            sim_google_ratchet(&mut g, &mut sk, &mut x_i, &mut y_i, &k3_c.clone(), &k3_s.clone(), message_1_from_user, message_2_from_user);
        });

        std::thread::sleep(std::time::Duration::from_millis(500));

        let mut stream = TcpStream::connect("127.0.0.1:9002").unwrap();
        let mut rk_i = sk;
        let mut large_y_i = g * y_i;
        let aead_nonce = &mut [0u8; 12];
        OsRng.fill_bytes(aead_nonce);


        let (x_i_plus_1, large_y_plus_one, rk_i_plus_2, output) =
            match alice::inner_double_ratchet(&mut&mut stream, aead_nonce, &&ad, g, &k3_c, &k3_s, rk_i, large_y_i, message_1_from_user) {
            Ok(value) => value,
            Err(value) => panic!("Alice: Error in inner_double_ratchet: {value}"),
        };

        assert_eq!(output, format!("Echo => {}", message_1_from_user));

        rk_i = rk_i_plus_2.into();
        large_y_i = large_y_plus_one;
        x_i = x_i_plus_1;

        let (_, _, _, output_2) =
        match alice::inner_double_ratchet(&mut&mut stream, aead_nonce, &&ad, g, &k3_c, &k3_s, rk_i, large_y_i, message_2_from_user) {
            Ok(value) => value,
            Err(value) => panic!("Alice: Error in inner_double_ratchet: {value}"),
        };

        assert_eq!(output_2, format!("Echo => {}", message_2_from_user));

        drop(stream);

        handle.join().unwrap();

        println!("Test double_ratchet finished.\n\n");
    }

    fn sim_google_ratchet(g: &mut ProjectivePoint, sk: &mut Output<Sha256>, x_i: &mut Scalar, y_i: &mut Scalar, k3_c: &[u8; 32], k3_s: &[u8; 32], message_1_from_user: &str, message_2_from_user: &str) {
        let listener = TcpListener::bind("127.0.0.1:9002").unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        let aead_nonce = &mut [0u8; 12];
        OsRng.fill_bytes(aead_nonce);
        let ad = b"Alice,Google,";

        let mut rk_i = sk;
        let mut _large_x_i = g.clone() * x_i.clone();
        let mut y_i = y_i;

        let (large_x_plus_one, y_i_plus_1, mut rk_i_plus_2, output) = match google::inner_double_ratchet(&k3_c, &k3_s, &mut &mut stream, aead_nonce, &&ad, *g, *rk_i, *y_i) {
            Ok(value) => value,
            Err(value) => panic!("Google: Error in inner_double_ratchet: {value}"),
        };

        assert_eq!(output, message_1_from_user);

        rk_i = (&mut rk_i_plus_2).into();
        _large_x_i = large_x_plus_one;
        *y_i = y_i_plus_1;

        let (_, _, _, output_2) = match google::inner_double_ratchet(&k3_c, &k3_s, &mut &mut stream, aead_nonce, &&ad, *g, *rk_i, *y_i) {
            Ok(value) => value,
            Err(value) => panic!("Google: Error in inner_double_ratchet: {value}"),
        };

        assert_eq!(output_2, message_2_from_user);

        drop(stream);
        drop(listener);
    }

    #[test]
    fn test_pqtls() {
        let ad = b"Alice,Google,";
        let mut ca = CA::new();
        let mut ca_clone = ca.clone();

        let handle = std::thread::spawn(move || {
            let listener = TcpListener::bind("127.0.0.1:9003").unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            let (k1_c, k1_s, k2_c, k2_s, k3_c, k3_s) = google::pq_tls(&mut stream, &mut ca_clone, ad);

            drop(stream);
            drop(listener);

            (k1_c, k1_s, k2_c, k2_s, k3_c, k3_s)
        });

        std::thread::sleep(std::time::Duration::from_millis(500));

        let mut stream = TcpStream::connect("127.0.0.1:9003").unwrap();

        let (alice_k1_c, alice_k1_s, alice_k2_c, alice_k2_s, alice_k3_c, alice_k3_s) = alice::pq_tls(&mut stream, &mut ca, ad);

        let result = handle.join().unwrap();
        let (google_k1_c, google_k1_s, google_k2_c, google_k2_s, google_k3_c, google_k3_s) = result;

        assert_eq!(alice_k1_c, google_k1_c);
        assert_eq!(alice_k1_s, google_k1_s);
        assert_eq!(alice_k2_c, google_k2_c);
        assert_eq!(alice_k2_s, google_k2_s);
        assert_eq!(alice_k3_c, google_k3_c);
        assert_eq!(alice_k3_s, google_k3_s);

        drop(stream);

        println!("Test pqtls finished.\n\n");
    }
}