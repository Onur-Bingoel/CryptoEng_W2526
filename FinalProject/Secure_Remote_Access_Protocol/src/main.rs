use crate::alice::alice;
use crate::crypto::hash2curve::hash2curve_demo;
use crate::crypto::participant;
use crate::google::google;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::hash2curve::ExpandMsgXmd;
use elliptic_curve::{Field, PrimeField};
use hmac::digest::Digest;
use image::EncodableLayout;
use k256::ProjectivePoint;
use ml_kem::KemCore;
use rand::RngCore;
use sha3::Sha3_256;

mod crypto;
mod alice;
mod google;

fn main() {
    let mut ca = participant::CA::new();
    let mut ca_clone = ca.clone();

    let len = 16;
    let mut random_bytes = vec![0u8; len];
    rand::rng().fill_bytes(&mut random_bytes);
    let mut g: ProjectivePoint =
        hash2curve_demo::<k256::Secp256k1, ExpandMsgXmd<Sha3_256>>(random_bytes.as_bytes())
            .expect("hash2curve_demo (k256 + SHA3-256) failed");

    let handle = std::thread::spawn(move || {
        google(&mut ca_clone, &mut g);
    });

    std::thread::sleep(std::time::Duration::from_millis(500));

    alice(&mut ca, &mut g);

    handle.join().unwrap();
}