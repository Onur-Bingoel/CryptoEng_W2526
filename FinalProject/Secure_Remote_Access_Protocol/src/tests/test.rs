#![allow(unused)]
mod tests {
    use crate::crypto::participant::{DatabaseContent, Message, User, CA};
    use crate::{client, crypto, server};
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
        println!("Testing register and login");

        let mut ca = CA::new();
        let mut ca_clone = ca.clone();
        let mut g: ProjectivePoint = ProjectivePoint::random(&mut OsRng);

        // start Google server in a separate thread
        let handle = std::thread::spawn(move || {
            sim_google(&mut ca_clone, &mut g);
        });

        std::thread::sleep(std::time::Duration::from_millis(500));

        let mut stream = TcpStream::connect("127.0.0.1:9001").unwrap();
        let mut aead_nonce: [u8; 12] = [0u8; 12];
        
        let ad = b"Alice,Google,";
        let username = "alice";
        let pw = "12345";

        // register return true if an error occurred
        let (_k1_c, _k1_s, _k2_c, _k2_s, k3_c, _k3_s) = client::pqtls::pq_tls(&mut stream, &mut ca, ad);
        assert!(!client::opaque_register::register(k3_c, &mut stream, &mut aead_nonce, &ad, &username, &pw));

        // login return true if an error occurred
        let (_k1_c, _k1_s, _k2_c, _k2_s, k3_c, k3_s) = client::pqtls::pq_tls(&mut stream, &mut ca, ad);
        assert!(!client::opaque_login::login(k3_c, k3_s, &mut stream, &mut aead_nonce, &ad, g, &username, &pw));

        drop(stream);

        handle.join().unwrap();

        println!("Test register_and_login finished.");
        println!("-------------------------------------------------------\n\n");
    }

    fn sim_google(ca: &mut CA, g: &mut ProjectivePoint) {
        // simulate Google server for register and login test
        let listener = TcpListener::bind("127.0.0.1:9001").unwrap();
        let (mut stream, _) = listener.accept().unwrap();

        let mut aead_nonce: [u8; 12] = [0u8; 12];
        let ad = b"Alice,Google,";
        let mut database: HashMap<Vec<u8>, DatabaseContent> = HashMap::new();

        // start pqtls and receive message from Alice
        let (_k1_c, _k1_s, _k2_c, _k2_s, k3_c, _k3_s) = server::pqtls::pq_tls(&mut stream, ca, ad);

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

        // register return true if an error occurred
        assert!(!server::opaque_register::register(
            &mut aead_nonce,
            &ad,
            &mut database,
            *g,
            &mut username,
            &mut content
        ));

        // start pqtls and receive message from Alice
        let (_k1_c, _k1_s, _k2_c, _k2_s, k3_c, k3_s) = server::pqtls::pq_tls(&mut stream, ca, ad);

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

        // login return true if an error occurred
        assert!(!server::opaque_login::login(
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
    fn test_wrong_password_and_username() {
        println!("Testing login with wrong username and password");

        let mut ca = CA::new();
        let mut ca_clone = ca.clone();
        let mut g: ProjectivePoint = ProjectivePoint::random(&mut OsRng);

        // start Google server in a separate thread
        let handle = std::thread::spawn(move || {
            sim_google_for_error_case(&mut ca_clone, &mut g);
        });

        std::thread::sleep(std::time::Duration::from_millis(500));

        let mut stream = TcpStream::connect("127.0.0.1:9002").unwrap();
        let mut aead_nonce: [u8; 12] = [0u8; 12];

        let ad = b"Alice,Google,";
        let username = "alice";
        let pw = "12345";
        let wrong_username = "alice2";
        let wrong_pw = "123456";

        // register return true if an error occurred
        let (_k1_c, _k1_s, _k2_c, _k2_s, k3_c, _k3_s) = client::pqtls::pq_tls(&mut stream, &mut ca, ad);
        assert!(!client::opaque_register::register(k3_c, &mut stream, &mut aead_nonce, &ad, &username, &pw));

        // Test wrong password
        // login return true if an error occurred. Error is expected here.
        let (_k1_c, _k1_s, _k2_c, _k2_s, k3_c, k3_s) = client::pqtls::pq_tls(&mut stream, &mut ca, ad);
        assert!(client::opaque_login::login(k3_c, k3_s, &mut stream, &mut aead_nonce, &ad, g, &username, &wrong_pw));
        // In case of a wrong password, the client needs to send a reset request
        User::send_bytes(&mut stream, &Message::Reset {});

        // Test wrong username
        // login return true if an error occurred. Error is expected here.
        let (_k1_c, _k1_s, _k2_c, _k2_s, k3_c, k3_s) = client::pqtls::pq_tls(&mut stream, &mut ca, ad);
        assert!(client::opaque_login::login(k3_c, k3_s, &mut stream, &mut aead_nonce, &ad, g, &wrong_username, &pw));

        drop(stream);

        handle.join().unwrap();

        println!("Test register_and_login finished.");
        println!("-------------------------------------------------------\n\n");
    }

    fn sim_google_for_error_case(ca: &mut CA, g: &mut ProjectivePoint) {
        // simulate Google server for register and login test with wrong username and password
        let listener = TcpListener::bind("127.0.0.1:9002").unwrap();
        let (mut stream, _) = listener.accept().unwrap();

        let mut aead_nonce: [u8; 12] = [0u8; 12];
        let ad = b"Alice,Google,";
        let mut database: HashMap<Vec<u8>, DatabaseContent> = HashMap::new();

        // start pqtls and receive message from Alice
        let (_k1_c, _k1_s, _k2_c, _k2_s, k3_c, _k3_s) = server::pqtls::pq_tls(&mut stream, ca, ad);

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

        // register return true if an error occurred.
        assert!(!server::opaque_register::register(
            &mut aead_nonce,
            &ad,
            &mut database,
            *g,
            &mut username,
            &mut content
        ));

        // Test wrong password.
        // start pqtls and receive message from Alice
        let (_k1_c, _k1_s, _k2_c, _k2_s, k3_c, k3_s) = server::pqtls::pq_tls(&mut stream, ca, ad);

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

        // login return true if an error occurred. Error is expected here.
        assert!(server::opaque_login::login(
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

        // Test wrong username.
        // start pqtls and receive message from Alice
        let (_k1_c, _k1_s, _k2_c, _k2_s, k3_c, k3_s) = server::pqtls::pq_tls(&mut stream, ca, ad);

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

        // login return true if an error occurred. Error is expected here.
        assert!(server::opaque_login::login(
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
        // In case of a wrong username, the server needs to send a reset request
        User::send_bytes(&mut stream, &Message::Reset {});

        drop(stream);
        drop(listener);
    }

    #[test]
    fn test_double_ratchet() {
        println!("Testing double_ratchet");

        let ad = b"Alice,Google,";
        let mut g: ProjectivePoint = ProjectivePoint::random(&mut OsRng);
        
        let len = 16;
        let mut random_bytes = vec![0u8; len];
        OsRng.fill_bytes(&mut random_bytes);
        
        let (mut sk, _) = crypto::key_schedule::extract(None, random_bytes.as_bytes());
        let mut x_i = Scalar::random(&mut OsRng);
        let mut y_i = Scalar::random(&mut OsRng);
        let message_1_from_user = "Hello, world!";
        let message_2_from_user = "How are you?";

        // start Google server in a separate thread
        let handle = std::thread::spawn(move || {
            sim_google_ratchet(&mut g, &mut sk, &mut x_i, &mut y_i, message_1_from_user, message_2_from_user);
        });

        std::thread::sleep(std::time::Duration::from_millis(500));

        let mut stream = TcpStream::connect("127.0.0.1:9003").unwrap();
        let mut rk_i = sk;
        let mut large_y_i = g * y_i;
        let aead_nonce = &mut [0u8; 12];
        OsRng.fill_bytes(aead_nonce);

        // start first double_ratchet iteration with first message
        let (x_i_plus_1, large_y_plus_one, rk_i_plus_2, output) =
            match client::double_ratchet::double_ratchet_iteration(&mut&mut stream, aead_nonce, &&ad, g, rk_i, large_y_i, message_1_from_user) {
            Ok(value) => value,
            Err(value) => panic!("Alice: Error in inner_double_ratchet: {value}"),
        };
        // check if output is correct
        assert_eq!(output, format!("Echo => {}", message_1_from_user));

        rk_i = rk_i_plus_2.into();
        large_y_i = large_y_plus_one;
        x_i = x_i_plus_1;

        // start second double_ratchet iteration with second message
        let (x_i_plus_2, large_y_plus_two, rk_i_plus_4, output_2) =
        match client::double_ratchet::double_ratchet_iteration(&mut&mut stream, aead_nonce, &&ad, g, rk_i, large_y_i, message_2_from_user) {
            Ok(value) => value,
            Err(value) => panic!("Alice: Error in inner_double_ratchet: {value}"),
        };

        // check if output is correct and if the ratchet keys and DH values have changed
        assert_eq!(output_2, format!("Echo => {}", message_2_from_user));
        assert_ne!(rk_i, rk_i_plus_4.into());
        assert_ne!(large_y_i, large_y_plus_two);
        assert_ne!(x_i, x_i_plus_2);

        drop(stream);

        handle.join().unwrap();

        println!("Test double_ratchet finished.");
        println!("-------------------------------------------------------\n\n");
    }

    fn sim_google_ratchet(g: &mut ProjectivePoint, sk: &mut Output<Sha256>, x_i: &mut Scalar, y_i: &mut Scalar, message_1_from_user: &str, message_2_from_user: &str) {
        // simulate Google server for double_ratchet test
        let listener = TcpListener::bind("127.0.0.1:9003").unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        let aead_nonce = &mut [0u8; 12];
        OsRng.fill_bytes(aead_nonce);
        let ad = b"Alice,Google,";

        let mut rk_i = sk;
        let mut _large_x_i = g.clone() * x_i.clone();
        let y_i = y_i;

        // start first double_ratchet iteration with first message
        let (large_x_plus_one, y_i_plus_1, mut rk_i_plus_2, output) = match server::double_ratchet::double_ratchet_iteration(&mut &mut stream, aead_nonce, &&ad, *g, *rk_i, *y_i) {
            Ok(value) => value,
            Err(value) => panic!("Google: Error in inner_double_ratchet: {value}"),
        };

        // check if output is correct
        assert_eq!(output, message_1_from_user);

        rk_i = (&mut rk_i_plus_2).into();
        _large_x_i = large_x_plus_one;
        *y_i = y_i_plus_1;

        // start second double_ratchet iteration with second message
        let (_, _, _, output_2) = match server::double_ratchet::double_ratchet_iteration(&mut &mut stream, aead_nonce, &&ad, *g, *rk_i, *y_i) {
            Ok(value) => value,
            Err(value) => panic!("Google: Error in inner_double_ratchet: {value}"),
        };

        // check if output is correct
        assert_eq!(output_2, message_2_from_user);

        drop(stream);
        drop(listener);
    }

    #[test]
    fn test_pqtls() {
        println!("Testing pqtls");

        let ad = b"Alice,Google,";
        let mut ca = CA::new();
        let mut ca_clone = ca.clone();

        // start Google server in a separate thread
        let handle = std::thread::spawn(move || {
            let listener = TcpListener::bind("127.0.0.1:9004").unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            // start pqtls on server side
            let (k1_c, k1_s, k2_c, k2_s, k3_c, k3_s) = server::pqtls::pq_tls(&mut stream, &mut ca_clone, ad);

            drop(stream);
            drop(listener);

            (k1_c, k1_s, k2_c, k2_s, k3_c, k3_s)
        });

        std::thread::sleep(std::time::Duration::from_millis(500));

        let mut stream = TcpStream::connect("127.0.0.1:9004").unwrap();

        // start pqtls on client side
        let (alice_k1_c, alice_k1_s, alice_k2_c, alice_k2_s, alice_k3_c, alice_k3_s) = client::pqtls::pq_tls(&mut stream, &mut ca, ad);

        let result = handle.join().unwrap();
        let (google_k1_c, google_k1_s, google_k2_c, google_k2_s, google_k3_c, google_k3_s) = result;

        // compare client and server keys
        assert_eq!(alice_k1_c, google_k1_c);
        assert_eq!(alice_k1_s, google_k1_s);
        assert_eq!(alice_k2_c, google_k2_c);
        assert_eq!(alice_k2_s, google_k2_s);
        assert_eq!(alice_k3_c, google_k3_c);
        assert_eq!(alice_k3_s, google_k3_s);

        drop(stream);

        println!("Test pqtls finished.");
        println!("-------------------------------------------------------\n\n");
    }
}