use crate::crypto;
use crate::crypto::hash2curve::hash2curve_demo;
use crate::crypto::participant::DatabaseContent;
use aes_gcm::aead::OsRng;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::hash2curve::ExpandMsgXmd;
use elliptic_curve::Field;
use hmac::digest::Digest;
use image::EncodableLayout;
use k256::{ProjectivePoint, Scalar};
use rand_core::RngCore;
use sha3::Sha3_256;
use std::collections::HashMap;
use crate::server::google::println;

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
        println(&*format!("Google: Registering user: {}", String::from_utf8_lossy(username)));
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
        println("Google: Client keys saved.");
    };
    false
}