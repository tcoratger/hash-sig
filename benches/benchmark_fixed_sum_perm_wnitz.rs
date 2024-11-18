use criterion::Criterion;
use hashsig::onetimesig::fixed_sum_permuted_winternitz::FixedSumPermutedWinternitzSha;

#[path = "benchmark_templates_ots.rs"]
mod benchmark_templates;
use benchmark_templates::{
    _benchmark_ots_gen_template, _benchmark_ots_sign_template, _benchmark_ots_verify_template,
};

pub fn fixed_sum_permuted_winternitz_bench(c: &mut Criterion) {
    // Benchmark for key generation
    _benchmark_ots_gen_template::<FixedSumPermutedWinternitzSha>(
        c,
        "Fixed-Sum-Permuted-Winternitz-Sha",
    );

    // Benchmark for signing
    _benchmark_ots_sign_template::<FixedSumPermutedWinternitzSha>(
        c,
        "Fixed-Sum-Permuted-Winternitz-Sha",
    );

    // Benchmark for verification
    _benchmark_ots_verify_template::<FixedSumPermutedWinternitzSha>(
        c,
        "Fixed-Sum-Permuted-Winternitz-Sha",
    );
}
