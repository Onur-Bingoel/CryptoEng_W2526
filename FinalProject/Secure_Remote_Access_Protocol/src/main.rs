use crate::crypto::participant;
use elliptic_curve::Group;
use k256::ProjectivePoint;
use rand_core::OsRng;
use crate::client::alice::alice;
use crate::server::google::google;

mod crypto;
mod tests;
mod client;
mod server;

fn main() {
    let mut ca = participant::CA::new();
    let mut ca_clone = ca.clone();
    let mut g: ProjectivePoint = ProjectivePoint::random(&mut OsRng);

    let handle = std::thread::spawn(move || {
        google(&mut ca_clone, &mut g);
    });

    std::thread::sleep(std::time::Duration::from_millis(500));

    alice(&mut ca, &mut g);

    handle.join().unwrap();
}