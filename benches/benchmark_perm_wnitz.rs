use criterion::Criterion;
use hashsig::onetimesig::permuted_winternitz::PermutedWinternitzSha;
use hashsig::onetimesig::OneTimeSignatureScheme;
use rand::rngs::OsRng;

pub fn permuted_winternitz_bench(c: &mut Criterion) {
    let mut rng = OsRng;

    // benchmark for key generation
    c.bench_function("Permuted-Winternitz-Sha: generate a key pair", |b| {
        b.iter(|| {
            let (_pk, _sk) = PermutedWinternitzSha::gen::<OsRng>(&mut rng);
        });
    });

    // benchmark for signing
    let (pk, sk) = PermutedWinternitzSha::gen::<OsRng>(&mut rng); // Generate a key pair
    let digest = [0u8; 32]; // Example message digest
    c.bench_function("Permuted-Winternitz-Sha: sign a message", |b| {
        b.iter(|| PermutedWinternitzSha::sign(&sk, &digest));
    });

    // benchmark for verification
    let sig = PermutedWinternitzSha::sign(&sk, &digest); // Sign the message
    c.bench_function("Permuted-Winternitz-Sha: verify a signature", |b| {
        b.iter(|| PermutedWinternitzSha::verify(&pk, &digest, &sig));
    });
}
