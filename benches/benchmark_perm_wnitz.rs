use criterion::Criterion;
use hashsig::onetimesig::permuted_winternitz::PermutedWinternitzSha;
use hashsig::onetimesig::OneTimeSignatureScheme;
use rand::rngs::OsRng;
use rand::RngCore;

pub fn permuted_winternitz_bench(c: &mut Criterion) {
    let mut rng = OsRng;

    // Benchmark for key generation
    c.bench_function("Perm-Winternitz-Sha: generate a key pair", |b| {
        b.iter(|| {
            let (_pk, _sk) = PermutedWinternitzSha::gen::<OsRng>(&mut rng);
        });
    });

    // Generate a key pair to use in the signing and verification benchmarks
    let (pk, sk) = PermutedWinternitzSha::gen::<OsRng>(&mut rng);

    // Benchmark for signing, with a new random digest each iteration
    c.bench_function("Perm-Winternitz-Sha: sign a message", |b| {
        b.iter(|| {
            let mut digest = [0u8; 32];
            rng.fill_bytes(&mut digest); // Fill the digest with random bytes
            PermutedWinternitzSha::sign(&sk, &digest)
        });
    });

    // Benchmark for verification
    c.bench_function("Perm-Winternitz-Sha: verify a signature", |b| {
        b.iter_batched(
            || {
                // Setup phase: generate a new random digest and corresponding signature
                let mut digest = [0u8; 32];
                rng.fill_bytes(&mut digest);
                let sig = PermutedWinternitzSha::sign(&sk, &digest);
                (digest, sig)
            },
            |(digest, sig)| {
                // Benchmark only the verification step
                PermutedWinternitzSha::verify(&pk, &digest, &sig)
            },
            criterion::BatchSize::SmallInput
        );
    });
}
