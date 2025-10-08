//! Benchmark suite comparing `HashTree::new` (scalar) vs `HashTree::new_packed` (SIMD).
//!
//! This benchmark tests three challenging scenarios:
//! 1. **Large dense tree** (65K leaves): Tests raw throughput with maximum parallelism
//! 2. **Sparse high offset tree** (10K leaves at offset 100K): Tests memory locality
//! 3. **Medium irregular tree** (12345 leaves): Tests edge case handling with non-power-of-2 sizes
//!
//! # Running the benchmarks
//!
//! ```bash
//! # Run all hashtree benchmarks
//! cargo bench --bench benchmark
//!
//! # Run specific scenario
//! cargo bench --bench benchmark -- "large_dense"
//! cargo bench --bench benchmark -- "sparse_high_offset"
//! cargo bench --bench benchmark -- "medium_irregular"
//!
//! # Compare scalar vs packed for a scenario
//! cargo bench --bench benchmark -- "packed/large_dense"
//! cargo bench --bench benchmark -- "scalar/large_dense"
//! ```
//!
//! # Output interpretation
//!
//! The benchmarks will show timing for each scenario. A typical result might look like:
//! ```text
//! HashTree: new vs new_packed/scalar/large_dense
//!                         time:   [45.2 ms 45.5 ms 45.8 ms]
//! HashTree: new vs new_packed/packed/large_dense
//!                         time:   [12.3 ms 12.5 ms 12.7 ms]
//! ```
//!
//! This would indicate ~3.6x speedup from SIMD for the large dense tree.

use criterion::{BenchmarkId, Criterion};
use hashsig::symmetric::{
    tweak_hash::TweakableHash, tweak_hash::poseidon::PoseidonTweakHash, tweak_hash_tree::HashTree,
};
use p3_koala_bear::{KoalaBear, PackedKoalaBearNeon};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::hint::black_box;

// Use the same parameters as in the signature instantiations
type F = KoalaBear;
type P = PackedKoalaBearNeon;
type TestTH = PoseidonTweakHash<4, 4, 3, 9, 128>;
const HASH_LEN: usize = 4;
const TWEAK_LEN: usize = 3;

/// Benchmark HashTree::new vs new_packed across various challenging dimensions.
pub fn bench_function_hashtree(c: &mut Criterion) {
    let mut group = c.benchmark_group("HashTree: new vs new_packed");

    // Challenging configurations: (depth, num_leafs, start_index, description)
    let configs = [
        (16, 65536, 0, "large_dense"),
        (18, 10000, 100000, "sparse_high_offset"),
        (14, 12345, 1000, "medium_irregular"),
    ];

    for (depth, num_leafs, start_index, description) in configs {
        let seed = [42u8; 32];
        let parameter = TestTH::rand_parameter(&mut StdRng::from_seed(seed));

        // Generate leaf hashes
        let leafs_hashes: Vec<[F; HASH_LEN]> = (0..num_leafs)
            .map(|i| {
                let leaf = vec![TestTH::rand_domain(&mut StdRng::from_seed([i as u8; 32]))];
                TestTH::apply(
                    &parameter,
                    &TestTH::tree_tweak(0, (start_index + i) as u32),
                    &leaf,
                )
            })
            .collect();

        // // Benchmark scalar version
        // group.bench_function(BenchmarkId::new("scalar", description), |b| {
        //     b.iter(|| {
        //         let mut rng = StdRng::from_seed(seed);
        //         let tree = HashTree::<TestTH>::new(
        //             black_box(&mut rng),
        //             black_box(depth),
        //             black_box(start_index),
        //             black_box(&parameter),
        //             black_box(leafs_hashes.clone()),
        //         );
        //         black_box(tree);
        //     });
        // });

        // Benchmark packed (SIMD) version
        group.bench_function(BenchmarkId::new("packed", description), |b| {
            b.iter(|| {
                let mut rng = StdRng::from_seed(seed);

                // let tree = HashTree::<TestTH>::new(
                //     black_box(&mut rng),
                //     black_box(depth),
                //     black_box(start_index),
                //     black_box(&parameter),
                //     black_box(leafs_hashes.clone()),
                // );
                // black_box(tree);

                let tree = HashTree::<TestTH>::new_packed::<_, HASH_LEN, TWEAK_LEN>(
                    black_box(&mut rng),
                    black_box(depth),
                    black_box(start_index),
                    black_box(&parameter),
                    black_box(leafs_hashes.clone()),
                );
                black_box(tree);
            });
        });
    }

    group.finish();
}
