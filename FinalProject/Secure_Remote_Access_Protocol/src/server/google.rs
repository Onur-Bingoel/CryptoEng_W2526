use crate::crypto;
use crate::crypto::participant::{DatabaseContent, Message, User, CA};
use crate::server::opaque_login::login;
use crate::server::opaque_register::register;
use crate::server::pqtls::pq_tls;
use hmac::digest::Digest;
use k256::ProjectivePoint;
use std::collections::HashMap;
use std::net::{TcpListener, TcpStream};
use std::panic;
use std::sync::atomic::{AtomicBool, Ordering};

pub(crate) static RECEIVED_RESET: AtomicBool = AtomicBool::new(false);
pub(crate) static DISABLE_PRINT: AtomicBool = AtomicBool::new(false);

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
                    println("Google: An error occurred, resetting connection...");
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
        println("Google: Establishing TLS connection");
        let (_k1_c, _k1_s, _k2_c, _k2_s, k3_c, k3_s) = pq_tls(&mut stream, ca, ad);
        println("Google: TLS connection established.");

        // Receive message from Alice
        println("Google: Waiting for message from Alice");
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

pub(crate) fn println(text: &str) {
    if DISABLE_PRINT.load(Ordering::Relaxed) {
        return;
    }
    println!("{}", text);
}