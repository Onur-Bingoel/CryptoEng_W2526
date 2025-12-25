use std::io::{self, Write};

/// Print a prompt and read one trimmed line from stdin.
pub fn read_line_prompt(prompt: &str) -> io::Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}