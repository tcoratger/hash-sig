use criterion::Criterion;
use hashsig::onetimesig::permuted_winternitz::PermutedWinternitzSha;

#[path = "benchmark_templates_ots.rs"]
mod benchmark_templates;
use benchmark_templates::{
    _benchmark_ots_gen_template, _benchmark_ots_sign_template, _benchmark_ots_verify_template,
};

pub fn permuted_winternitz_bench(c: &mut Criterion) {
    // Benchmark for key generation
    _benchmark_ots_gen_template::<PermutedWinternitzSha>(c, "Perm-Wnitz-Sha");

    // Benchmark for signing
    _benchmark_ots_sign_template::<PermutedWinternitzSha>(c, "Perm-Wnitz-Sha");

    // Benchmark for verification
    _benchmark_ots_verify_template::<PermutedWinternitzSha>(c, "Perm-Wnitz-Sha");
}
