use std::io::{self, Write};

/// Read one trimmed line from stdin.
pub fn read_line() -> io::Result<String> {
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}