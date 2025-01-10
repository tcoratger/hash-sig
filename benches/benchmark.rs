use criterion::{criterion_group, criterion_main};

mod benchmark_poseidon;
mod benchmark_sha;

// use benchmark_poseidon::bench_function_poseidon;
use benchmark_sha::bench_function_sha;

criterion_group!(benches, bench_function_sha);
// criterion_group!(benches, bench_function_poseidon);
criterion_main!(benches);
