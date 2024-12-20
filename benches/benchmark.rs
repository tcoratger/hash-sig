use criterion::{black_box, criterion_group, criterion_main, Criterion, SamplingMode};
use hashsig::{
    inc_encoding::target_sum::TargetSumEncoding,
    signature::{generalized_xmss::GeneralizedXMSSSignatureScheme, SignatureScheme},
    symmetric::{
        message_hash::{sha::Sha256MessageHash192x3, MessageHash},
        prf::hashprf::Sha256PRF,
        tweak_hash::sha::Sha256Tweak192192,
    },
};
use rand::{thread_rng, Rng};

/// A template for benchmarking signature schemes (key gen, signing, verification)
pub fn benchmark_signature_scheme<S: SignatureScheme>(c: &mut Criterion, description: &str) {
    let mut group = c.benchmark_group(format!("{} - signature_scheme", description));

    // key gen takes long, so don't do that many repetitions
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(10);

    let mut rng = thread_rng();

    const MESSAGE_LENGTH: usize = 64;

    group.bench_function(format!("{} - gen", description), |b| {
        b.iter(|| {
            // Benchmark key generation
            let _ = S::gen(black_box(&mut rng));
        });
    });

    group.sample_size(100);

    let (pk, sk) = S::gen(&mut rng);

    group.bench_function(format!("{} - sign", description), |b| {
        b.iter(|| {
            // Sample random test message
            let mut message = [0u8; MESSAGE_LENGTH];
            rng.fill(&mut message);

            // Sample random epoch
            let epoch = rng.gen_range(0..S::LIFETIME) as u64;

            // Benchmark signing
            let _ = S::sign(
                black_box(&mut rng),
                black_box(&sk),
                black_box(epoch),
                black_box(&message),
            );
        });
    });

    // Pre-generate messages, epochs, and signatures for verification
    let precomputed: Vec<(u64, [u8; MESSAGE_LENGTH], S::Signature)> = (0..2000)
        .map(|_| {
            let mut message = [0u8; MESSAGE_LENGTH];
            rng.fill(&mut message);
            let epoch = rng.gen_range(0..S::LIFETIME) as u64;
            let signature =
                S::sign(&mut rng, &sk, epoch, &message).expect("Signing should succeed");
            (epoch, message, signature)
        })
        .collect();

    // Verification benchmark
    group.bench_function(format!("{}_verify", description), |b| {
        b.iter(|| {
            // Randomly pick a precomputed signature to verify
            let (epoch, message, signature) =
                black_box(&precomputed[rng.gen_range(0..precomputed.len())]);
            let _ = S::verify(
                black_box(&pk),
                *epoch,
                black_box(message),
                black_box(signature),
            );
        });
    });

    group.finish();
}

// Some example parameter settings to check if the benchmark works
// TODO: Use the actual parameters
type PRF = Sha256PRF<24>;
type TH = Sha256Tweak192192;
type MH = Sha256MessageHash192x3;
const CHUNK_SIZE: usize = 2;
const NUM_CHUNKS: usize = MH::OUTPUT_LENGTH * 8 / CHUNK_SIZE;
const MAX_CHUNK_VALUE: usize = (1 << CHUNK_SIZE) - 1;
const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
type IE = TargetSumEncoding<MH, CHUNK_SIZE, EXPECTED_SUM>;
const LOG_LIFETIME: usize = 20;
type SIG = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

fn bench_function(c: &mut Criterion) {
    benchmark_signature_scheme::<SIG>(c, "example");
}

criterion_group!(benches, bench_function);
criterion_main!(benches);
