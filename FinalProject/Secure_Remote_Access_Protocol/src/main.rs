use crate::client::alice::alice;
use crate::crypto::participant;
use crate::server::google;
use crate::server::google::google;
use inquire::Select;
use k256::ProjectivePoint;

mod crypto;
mod tests;
mod client;
mod server;

fn main() {
    let mut ca = participant::CA::new();
    let mut g: ProjectivePoint = ProjectivePoint::default();

    let options = vec!["Server", "Client", "Both"];
    let selection = Select::new("What do you want to start?", options.clone()).prompt();


    match selection {
        Ok(choice) => {
            match choice {
                "Server" => google(&mut ca, &mut g),
                "Client" => alice(&mut ca, &mut g),
                "Both" => {
                    google::DISABLE_PRINT.store(true, std::sync::atomic::Ordering::Relaxed);
                    let mut ca_clone = ca.clone();
                    let handle = std::thread::spawn(move || {
                        google(&mut ca_clone, &mut g);
                    });
                    alice(&mut ca, &mut g);

                    handle.join().unwrap();
                }
                _ => unreachable!(),
            }
        }

        Err(_) => {
            println!("Error: Invalid input");
            return;
        }
    }
}