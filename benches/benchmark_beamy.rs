use criterion::Criterion;
use hashsig::onetimesig::beamy::Beamy;
use hashsig::onetimesig::OneTimeSignatureScheme;
use hashsig::symmetric::hashprf::Sha256PRF;
use hashsig::symmetric::sha::Sha256Hash;
use rand::rngs::OsRng;

type BeamySha = Beamy<Sha256Hash, Sha256PRF>;

pub fn beamy_bench(c: &mut Criterion) {
    let mut rng = OsRng;

    // benchmark for key generation
    c.bench_function("Beamy-Sha: generate a key pair", |b| {
        b.iter(|| {
            let (_pk, _sk) = BeamySha::gen::<OsRng>(&mut rng);
        });
    });

    // benchmark for signing
    let (pk, sk) = BeamySha::gen::<OsRng>(&mut rng); // Generate a key pair
    let digest = [0u8; 32]; // Example message digest
    c.bench_function("Beamy-Sha: sign a message", |b| {
        b.iter(|| BeamySha::sign(&sk, &digest));
    });

    // benchmark for verification
    let sig = BeamySha::sign(&sk, &digest); // Sign the message
    c.bench_function("Beamy-Sha: verify a signature", |b| {
        b.iter(|| BeamySha::verify(&pk, &digest, &sig));
    });
}
