use criterion::Criterion;
use hashsig::onetimesig::winternitz::WinternitzSha;
use hashsig::onetimesig::OneTimeSignatureScheme;
use rand::rngs::OsRng;
use rand::RngCore;

pub fn winternitz_bench(c: &mut Criterion) {
    let mut rng = OsRng;

    // Benchmark for key generation
    c.bench_function("Wnitz-Sha: generate a key pair", |b| {
        b.iter(|| {
            let (_pk, _sk) = WinternitzSha::gen::<OsRng>(&mut rng);
        });
    });

    // Generate a key pair to use in the signing and verification benchmarks
    let (pk, sk) = WinternitzSha::gen::<OsRng>(&mut rng);

    // Benchmark for signing, with a new random digest each iteration
    c.bench_function("Wnitz-Sha: sign a message", |b| {
        b.iter(|| {
            let mut digest = [0u8; 32];
            rng.fill_bytes(&mut digest); // Fill the digest with random bytes
            WinternitzSha::sign(&sk, &digest)
        });
    });

    // Benchmark for verification
    c.bench_function("Wnitz-Sha: verify a signature", |b| {
        b.iter_batched(
            || {
                // Setup phase: generate a new random digest and corresponding signature
                let mut digest = [0u8; 32];
                rng.fill_bytes(&mut digest);
                let sig = WinternitzSha::sign(&sk, &digest);
                (digest, sig)
            },
            |(digest, sig)| {
                // Benchmark only the verification step
                WinternitzSha::verify(&pk, &digest, &sig)
            },
            criterion::BatchSize::SmallInput
        );
    });
}
