use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hashsig::symmetric::message_hash::poseidon::decode_to_chunks;
use hashsig::symmetric::message_hash::poseidon::encode_epoch;
use hashsig::symmetric::message_hash::poseidon::encode_message;
use hashsig::symmetric::tweak_hash::poseidon::poseidon_safe_domain_separator;
use hashsig::symmetric::tweak_hash::poseidon::PoseidonTweak;
use hashsig::symmetric::tweak_hash::sha::ShaTweak128192;
use hashsig::symmetric::tweak_hash::TweakableHash;
use hashsig::symmetric::tweak_hash_tree::build_tree;
use hashsig::MESSAGE_LENGTH;
use hashsig::TWEAK_SEPARATOR_FOR_CHAIN_HASH;
use hashsig::TWEAK_SEPARATOR_FOR_TREE_HASH;
use num_bigint::BigUint;
use rand::thread_rng;
use rand::Rng;
use zkhash::ark_ff::UniformRand;
use zkhash::fields::babybear::{FpBabyBear as F, FqConfig};
use zkhash::poseidon2::poseidon2::Poseidon2;
use zkhash::poseidon2::poseidon2_instance_babybear::{
    POSEIDON2_BABYBEAR_16_PARAMS, POSEIDON2_BABYBEAR_24_PARAMS,
};

const TWEAK_LEN: usize = 3;
const TREE_SEP: u64 = TWEAK_SEPARATOR_FOR_TREE_HASH as u64;
const CHAIN_SEP: u64 = TWEAK_SEPARATOR_FOR_CHAIN_HASH as u64;

// fn bench_tree_tweak(c: &mut Criterion) {
//     let tweak = PoseidonTweak::<20, 8, 2>::TreeTweak {
//         level: 42,
//         pos_in_level: 12345,
//     };

//     c.bench_function("tree_tweak_to_field_elements", |b| {
//         b.iter(|| {
//             let _ = tweak.to_field_elements::<TWEAK_LEN>();
//         })
//     });
// }

// fn bench_chain_tweak(c: &mut Criterion) {
//     let tweak = PoseidonTweak::<20, 8, 2>::ChainTweak {
//         epoch: 1337,
//         chain_index: 12,
//         pos_in_chain: 34,
//     };

//     c.bench_function("chain_tweak_to_field_elements", |b| {
//         b.iter(|| {
//             let _ = tweak.to_field_elements::<TWEAK_LEN>();
//         })
//     });
// }

// criterion_group!(tweak_benches, bench_tree_tweak, bench_chain_tweak);
// criterion_main!(tweak_benches);

//

// fn bench_encode_message(c: &mut Criterion) {
//     // Create a random message of MESSAGE_LENGTH bytes
//     let mut rng = thread_rng();
//     let mut message = [0u8; MESSAGE_LENGTH];
//     rng.fill(&mut message);

//     c.bench_function("encode_message", |b| {
//         b.iter(|| {
//             // Prevent the compiler from optimizing the input away
//             let _ = encode_message::<3>(black_box(&message));
//         })
//     });
// }

// criterion_group!(benches, bench_encode_message);
// criterion_main!(benches);

//

// const TWEAK_LEN_FE: usize = 1000;

// fn bench_encode_epoch(c: &mut Criterion) {
//     c.bench_function("encode_epoch (optimized, u128)", |b| {
//         b.iter(|| {
//             let epoch = black_box(u32::MAX);
//             let _fe: [F; TWEAK_LEN_FE] = encode_epoch::<TWEAK_LEN_FE>(epoch);
//             black_box(_fe);
//         });
//     });
// }

// criterion_group!(benches, bench_encode_epoch);
// criterion_main!(benches);

//

// /// Generate a random input of `HASH_LEN_FE` field elements
// fn generate_random_input<const HASH_LEN_FE: usize>() -> [F; HASH_LEN_FE] {
//     let mut rng = rand::thread_rng();
//     std::array::from_fn(|_| F::rand(&mut rng))
// }

// /// Benchmark function
// fn benchmark_decode_to_chunks(c: &mut Criterion) {
//     const NUM_CHUNKS: usize = 256;
//     const CHUNK_SIZE: usize = 8;
//     const HASH_LEN_FE: usize = 32;

//     let input = generate_random_input::<HASH_LEN_FE>();

//     c.bench_function("decode_to_chunks_256x8_from_32fe", |b| {
//         b.iter(|| {
//             let result = decode_to_chunks::<NUM_CHUNKS, CHUNK_SIZE, HASH_LEN_FE>(black_box(&input));
//             black_box(result);
//         })
//     });
// }

// criterion_group!(benches, benchmark_decode_to_chunks);
// criterion_main!(benches);

//

// type TH = ShaTweak128192;

// /// Benchmark for building a hash tree with 1024 leaves
// fn benchmark_build_tree_1024(c: &mut Criterion) {
//     let mut rng = thread_rng();

//     // Generate parameter and leaf hashes
//     let parameter = TH::rand_parameter(&mut rng);

//     let leafs: Vec<_> = (0..1024)
//         .map(|i| {
//             let leaf = [TH::rand_domain(&mut rng)];
//             TH::apply(&parameter, &TH::tree_tweak(0, i), &leaf)
//         })
//         .collect();

//     // Benchmark the build_tree function
//     c.bench_function("build_tree with 1024 leaves", |b| {
//         b.iter(|| {
//             let _tree = build_tree::<TH>(&parameter, leafs.clone());
//         });
//     });
// }

// criterion_group!(benches, benchmark_build_tree_1024);
// criterion_main!(benches);

//

fn bench_poseidon_safe_domain_separator(c: &mut Criterion) {
    let instance = Poseidon2::new(&POSEIDON2_BABYBEAR_24_PARAMS);

    // Array of parameters to stress test
    let params = [usize::MAX; 4];

    c.bench_function("poseidon_safe_domain_separator_1000_params", |b| {
        b.iter(|| {
            let _ = poseidon_safe_domain_separator::<4>(black_box(&instance), black_box(&params));
        });
    });
}

criterion_group!(benches, bench_poseidon_safe_domain_separator);
criterion_main!(benches);
