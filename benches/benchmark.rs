use criterion::{criterion_group, criterion_main};

use benchmark_lamport::lamport_bench;
use benchmark_wnitz::winternitz_bench;
use benchmark_beamy::beamy_bench;

mod benchmark_lamport;
mod benchmark_wnitz;
mod benchmark_beamy;

criterion_group!(benches, lamport_bench, winternitz_bench, beamy_bench);
criterion_main!(benches);
