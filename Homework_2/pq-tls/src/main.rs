use std::thread;
use pq_tls::run;

fn main() {
    thread::Builder::new()
        .stack_size(8 * 1024 * 1024) // z.B. 8 MB
        .spawn(|| run(false))
        .expect("Thread-Start fehlgeschlagen")
        .join()
        .expect("Thread-Abbruch");
}