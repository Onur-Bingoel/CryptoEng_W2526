use std::thread;
use std::time::{Duration, Instant};
use kem_tls::run as kem_run;
use pq_tls::run as pq_run;

const ITERATIONS: usize = 50;

fn benchmark<F>(name: &str, func: F) -> Vec<Duration>
where
    F: Fn(),
{
    let mut timings = Vec::with_capacity(ITERATIONS);
    func(); // Warm-up
    for _ in 0..ITERATIONS {
        let start = Instant::now();
        func();
        timings.push(start.elapsed());
    }
    println!("Finished benchmarking {}", name);
    timings
}

fn mean(data: &[Duration]) -> Duration {
    let total_ns: u128 = data.iter().map(|d| d.as_nanos()).sum();
    Duration::from_nanos((total_ns / data.len() as u128) as u64)
}

fn median(data: &[Duration]) -> Duration {
    let mut sorted = data.to_vec();
    sorted.sort();
    sorted[sorted.len() / 2]
}

fn std_dev(data: &[Duration], mean: Duration) -> Duration {
    let mean_ns = mean.as_nanos() as f64;
    let variance = data
        .iter()
        .map(|d| {
            let diff = d.as_nanos() as f64 - mean_ns;
            diff * diff
        })
        .sum::<f64>()
        / data.len() as f64;
    Duration::from_nanos(variance.sqrt() as u64)
}

fn print_results(name: &str, data: &[Duration]) {
    let mean_val = mean(data);
    let median_val = median(data);
    let std_val = std_dev(data, mean_val);
    let min = data.iter().min().unwrap();
    let max = data.iter().max().unwrap();

    println!("\n=== {} ===", name);
    println!("Runs: {}", data.len());
    println!("Mean time:   {:.6} ms", mean_val.as_secs_f64() * 1000.0);
    println!("Median time: {:.6} ms", median_val.as_secs_f64() * 1000.0);
    println!("Std dev:     {:.6} ms", std_val.as_secs_f64() * 1000.0);
    println!("Min time:    {:.6} ms", min.as_secs_f64() * 1000.0);
    println!("Max time:    {:.6} ms", max.as_secs_f64() * 1000.0);
}

fn run() {
    println!("Starting pq-tls vs kem-tls efficiency comparison...\n");

    let pq_timings = benchmark("pq-tls Handshake", || pq_run(true));
    let kem_timings = benchmark("kem-tls Handshake", || kem_run(true));

    print_results("pq-tls Handshake", &pq_timings);
    print_results("kem-tls Handshake", &kem_timings);

    let pq_mean = mean(&pq_timings).as_secs_f64();
    let kem_mean = mean(&kem_timings).as_secs_f64();

    println!("\n=== Relative Comparison ===");
    println!("pq-tls / kem-tls mean time ratio: {:.2}x", pq_mean / kem_mean);

    if pq_mean > kem_mean {
        println!("kem-tls is faster on average.");
    } else {
        println!("pq-tls is faster on average.");
    }
}

fn main() {
    thread::Builder::new()
        .stack_size(4 * 1024 * 1024)
        .spawn(run)
        .unwrap()
        .join()
        .unwrap();
}