use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hashsig::symmetric::message_hash::poseidon::encode_message;
use hashsig::symmetric::tweak_hash::poseidon::PoseidonTweak;
use hashsig::MESSAGE_LENGTH;
use hashsig::TWEAK_SEPARATOR_FOR_CHAIN_HASH;
use hashsig::TWEAK_SEPARATOR_FOR_TREE_HASH;
use num_bigint::BigUint;
use rand::thread_rng;
use rand::Rng;
use zkhash::fields::babybear::{FpBabyBear as F, FqConfig};

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

fn bench_encode_message(c: &mut Criterion) {
    // Create a random message of MESSAGE_LENGTH bytes
    let mut rng = thread_rng();
    let mut message = [0u8; MESSAGE_LENGTH];
    rng.fill(&mut message);

    c.bench_function("encode_message", |b| {
        b.iter(|| {
            // Prevent the compiler from optimizing the input away
            let _ = encode_message::<3>(black_box(&message));
        })
    });
}

criterion_group!(benches, bench_encode_message);
criterion_main!(benches);
