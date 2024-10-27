use criterion::{criterion_group, criterion_main};

use benchmark_perm_wnitz::beamy_bench;
use benchmark_lamport::lamport_bench;
use benchmark_wnitz::winternitz_bench;

mod benchmark_perm_wnitz;
mod benchmark_lamport;
mod benchmark_wnitz;

criterion_group!(benches, lamport_bench, winternitz_bench, beamy_bench);
criterion_main!(benches);
