use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use sha3::{Digest, Sha3_256};

fn main() -> io::Result<()>  {
    let target = "8yQ28QbbPQYfvpta2FBSgsZTGZlFdVYMhn7ePNbaKV8=";
    let target_digest = BASE64_STANDARD.decode(target).unwrap();

    let file = File::open("Dictionary.txt")?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        let digest = Sha3_256::digest(line.as_bytes());
        if digest.as_slice() == target_digest {
            println!("Found password: {}", line);
            break;
        }
    }

    Ok(())
}
