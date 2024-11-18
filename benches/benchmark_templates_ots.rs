use criterion::Criterion;
use hashsig::onetimesig::OneTimeSignatureScheme;
use rand::rngs::OsRng;

/// template benchmark for benchmarking key generation
pub fn _benchmark_ots_gen_template<OTS: OneTimeSignatureScheme>(
    c: &mut Criterion,
    scheme_name: &str,
) {
    let mut rng = OsRng;
    // Benchmark for key generation
    c.bench_function(&format!("{}: generate a key pair", scheme_name), |b| {
        b.iter(|| {
            let (_pk, _sk) = OTS::gen::<OsRng>(&mut rng);
        });
    });
}

/// template benchmark for benchmarking signing
pub fn _benchmark_ots_sign_template<OTS: OneTimeSignatureScheme>(
    c: &mut Criterion,
    scheme_name: &str,
) {
    let mut rng = OsRng;
    // Generate a key pair to use in the signing and verification benchmarks
    let (_pk, sk) = OTS::gen::<OsRng>(&mut rng);

    // Benchmark for signing, with a new random digest each iteration
    c.bench_function(&format!("{}: sign a digest", scheme_name), |b| {
        b.iter(|| {
            let digest = OTS::rand_digest::<OsRng>(&mut rng);
            OTS::sign(&sk, &digest)
        });
    });
}

/// template benchmark for benchmarking verification
pub fn _benchmark_ots_verify_template<OTS: OneTimeSignatureScheme>(
    c: &mut Criterion,
    scheme_name: &str,
) {
    let mut rng = OsRng;
    // Generate a key pair to use in the signing and verification benchmarks
    let (pk, sk) = OTS::gen::<OsRng>(&mut rng);

    // Benchmark for verification
    c.bench_function(&format!("{}: verify a signature", scheme_name), |b| {
        b.iter_batched(
            || {
                // Setup phase: generate a new random digest and corresponding signature
                let digest = OTS::rand_digest::<OsRng>(&mut rng);
                let sig = OTS::sign(&sk, &digest);
                (digest, sig)
            },
            |(digest, sig)| {
                // Benchmark only the verification step
                OTS::verify(&pk, &digest, &sig)
            },
            criterion::BatchSize::SmallInput,
        );
    });
}
