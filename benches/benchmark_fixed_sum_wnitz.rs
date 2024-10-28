use criterion::Criterion;

use hashsig::onetimesig::{fixed_sum_winternitz::FixedSumWinternitzSha, OneTimeSignatureScheme};
use rand::rngs::OsRng;

pub fn fixed_sum_winternitz_bench(c: &mut Criterion) {
    let mut rng = OsRng;

    // benchmark for key generation
    c.bench_function("Fixed-Sum-Winternitz-Sha: generate a key pair", |b| {
        b.iter(|| {
            let (_pk, _sk) = FixedSumWinternitzSha::gen::<OsRng>(&mut rng);
        });
    });

    // benchmark for signing
    let (pk, sk) = FixedSumWinternitzSha::gen::<OsRng>(&mut rng); // Generate a key pair
    let digest = [0u8; 32]; // Example message digest
    c.bench_function("Fixed-Sum-Winternitz-Sha: sign a message", |b| {
        b.iter(|| FixedSumWinternitzSha::sign(&sk, &digest));
    });

    // benchmark for verification
    let sig = FixedSumWinternitzSha::sign(&sk, &digest); // Sign the message
    c.bench_function("Fixed-Sum-Winternitz-Sha: verify a signature", |b| {
        b.iter(|| FixedSumWinternitzSha::verify(&pk, &digest, &sig));
    });
}
