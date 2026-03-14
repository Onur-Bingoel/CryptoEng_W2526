use crate::crypto::participant::{Message, User, CA};
use inquire::Select;
use k256::ProjectivePoint;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{io, panic};
use image::EncodableLayout;
use crate::client::opaque_login::login;
use crate::client::opaque_register::register;
use crate::client::pqtls::pq_tls;
use crate::crypto;

pub(crate) static RECEIVED_RESET: AtomicBool = AtomicBool::new(false);

pub fn alice(ca: &mut CA, group_element: &mut ProjectivePoint) {
    let mut stream = TcpStream::connect("127.0.0.1:9000").unwrap();
    loop {
        panic::set_hook(Box::new(|_| {
        }));
        match panic::catch_unwind(panic::AssertUnwindSafe(|| {
            match alice_inner(ca, group_element, &mut stream) {
                _ => panic!("Alice: Error in alice_inner"),
            }
        })) {
            _ => {
                if !RECEIVED_RESET.load(Ordering::Relaxed) {
                    println!("Alice: An error occurred, resetting connection");
                    User::send_bytes(&mut stream, &Message::Reset {});
                };
                RECEIVED_RESET.store(false, Ordering::Relaxed);
            }
        }
    }
}

pub fn alice_inner(ca: &mut CA, group_element: &mut ProjectivePoint, mut stream: &mut TcpStream) {
    let mut aead_nonce: [u8; 12] = [0u8; 12];
    let ad = b"Alice,Google,";
    let g = group_element.clone();
    let options = vec!["Login", "Register"];

    loop {
        println!("\n------------------------------------------------------------------\n");
        let selection = Select::new("Welcome, what would you like to do", options.clone()).prompt();

        println!("Enter username: ");
        let mut username = String::new();
        io::stdin()
            .read_line(&mut username)
            .expect("Error reading username");
        println!("Enter password: ");
        let mut pw = String::new();
        io::stdin()
            .read_line(&mut pw)
            .expect("Error reading password");

        // Establish TLS connection
        println!("Alice: Establishing TLS connection");
        let (_k1_c, _k1_s, _k2_c, _k2_s, k3_c, k3_s) = pq_tls(&mut stream, ca, ad);
        println!("Alice: TLS connection established");

        match selection {
            Ok(choice) => {
                match choice {
                    "Login" => {
                        if login(
                            k3_c, 
                            k3_s, 
                            &mut stream,
                            &mut aead_nonce,
                            &ad, 
                            g,
                            &username,
                            &pw
                        ) {
                            eprintln!("Alice: Login error");
                            return;
                        }
                    },
                    "Register" => {
                        if register(
                            k3_c,
                            &mut stream, 
                            &mut aead_nonce,
                            &ad, 
                            &username,
                            &pw
                        ) {
                            eprintln!("Alice: Register error");
                            return;
                        }
                    },
                    _ => unreachable!(),
                }
            },
            Err(_) => {
                eprintln!("Alice: Error reading selection");
                return;
            }
        }
    }
}

pub fn reconstruct_aead_message(msg: Message) -> Result<([u8; 12], Vec<u8>), bool> {
    let (nonce, aead_payload) = match msg {
        Message::AeadCiphertext { nonce, aead_payload } => (nonce, aead_payload),
        _ => {
            match msg {
                Message::Reset {} => (),
                _ => {
                    eprintln!("Alice: Unexpected message");
                    return Err(true);
                }
            }
            RECEIVED_RESET.store(true, Ordering::Relaxed);
            // panic!("Alice: Unexpected message")
            return Err(true);
        },
    };
    Ok((nonce, aead_payload))
}

pub fn encrypt(k3_c: &[u8; 32], aead_nonce: &&mut [u8; 12], ad: &&&[u8; 13], msg: Vec<u8>) -> Result<Vec<u8>, bool> {
    let cypher_text: Vec<u8> = match crypto::aead::encrypt(&k3_c, &aead_nonce, msg.as_bytes(), &ad.to_vec()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Alice: Encrypt error: {e}");
            return Err(true);
        }
    };
    Ok(cypher_text)
}

pub fn decrypt(k3_s: &[u8; 32], ad: &&&[u8; 13], nonce: &[u8; 12], ciphertext: &Vec<u8>) -> Result<Vec<u8>, bool> {
    let decrypted_msg: Vec<u8> = match crypto::aead::decrypt(&k3_s, &nonce, &ciphertext, &ad.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Alice: Decrypt error: {e}");
            return Err(true);
        }
    };
    Ok(decrypted_msg)
}