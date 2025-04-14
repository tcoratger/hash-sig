use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hashsig::symmetric::tweak_hash::poseidon::PoseidonTweak;
use hashsig::TWEAK_SEPARATOR_FOR_CHAIN_HASH;
use hashsig::TWEAK_SEPARATOR_FOR_TREE_HASH;
use num_bigint::BigUint;
use zkhash::fields::babybear::{FpBabyBear as F, FqConfig};

const TWEAK_LEN: usize = 3;
const TREE_SEP: u64 = TWEAK_SEPARATOR_FOR_TREE_HASH as u64;
const CHAIN_SEP: u64 = TWEAK_SEPARATOR_FOR_CHAIN_HASH as u64;

fn bench_tree_tweak(c: &mut Criterion) {
    let tweak = PoseidonTweak::<20, 8, 2>::TreeTweak {
        level: 42,
        pos_in_level: 12345,
    };

    c.bench_function("tree_tweak_to_field_elements", |b| {
        b.iter(|| {
            let _ = tweak.to_field_elements::<TWEAK_LEN>();
        })
    });
}

fn bench_chain_tweak(c: &mut Criterion) {
    let tweak = PoseidonTweak::<20, 8, 2>::ChainTweak {
        epoch: 1337,
        chain_index: 12,
        pos_in_chain: 34,
    };

    c.bench_function("chain_tweak_to_field_elements", |b| {
        b.iter(|| {
            let _ = tweak.to_field_elements::<TWEAK_LEN>();
        })
    });
}

criterion_group!(tweak_benches, bench_tree_tweak, bench_chain_tweak);
criterion_main!(tweak_benches);
