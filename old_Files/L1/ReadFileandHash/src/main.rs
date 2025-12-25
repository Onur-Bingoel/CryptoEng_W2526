use sha3::{Digest, Sha3_512};
use base64::{engine::general_purpose, Engine as _};
use std::fs::File;
use std::io::{self, Read, Write};

fn main() {
    println!("SHA3-512 File Hasher");
    println!("Type a filename to hash (or 'exit' to quit):");

    loop {
        print!("> ");
        // flush stdout so prompt appears immediately
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            eprintln!("Error reading input. Try again.");
            continue;
        }

        let filename = input.trim();
        if filename.eq_ignore_ascii_case("exit") {
            println!("Bye!");
            break;
        }

        match File::open(filename) {
            Ok(mut file) => {
                let mut buffer = Vec::new();
                if let Err(e) = file.read_to_end(&mut buffer) {
                    eprintln!("Failed to read '{}': {}", filename, e);
                    continue;
                }

                // Compute SHA3-512
                let mut hasher = Sha3_512::new();
                hasher.update(&buffer);
                let result = hasher.finalize();
                println!("SHA3-512 hex code: {:x}", result);
                println!("SHA3-512 Base64 code: {}", general_purpose::STANDARD.encode(result));
                println!("SHA3-512({}) = {:?}", filename, result); // Print the bytes, not the base64 code
            }
            Err(e) => {
                eprintln!("Cannot open '{}': {}", filename, e);
            }
        }
    }
}
