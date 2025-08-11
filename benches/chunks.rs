use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use hashsig::symmetric::message_hash::bytes_to_chunks;
use rand::RngCore;
use rand::SeedableRng;
use rand::rngs::SmallRng;

fn make_data(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = SmallRng::seed_from_u64(seed);
    let mut v = vec![0u8; len];
    rng.fill_bytes(&mut v);
    v
}

fn bench_bytes_to_chunks(c: &mut Criterion) {
    let sizes = [0usize, 16, 64, 256, 1024, 4096, 65536];
    let chunk_sizes = [1usize, 2, 4, 8];

    let mut group = c.benchmark_group("bytes_to_chunks");

    for &len in &sizes {
        // Pre-generate deterministic data once per size
        let data = make_data(len, 0xC0FFEEu64 ^ (len as u64));
        group.throughput(Throughput::Bytes(len as u64));

        for &cs in &chunk_sizes {
            group.bench_with_input(
                BenchmarkId::new(format!("iter_cs{cs}"), len),
                &(data.as_slice(), cs),
                |b, &(bytes, chunk_size)| {
                    b.iter(|| {
                        black_box(bytes_to_chunks(black_box(bytes), black_box(chunk_size)));
                    });
                },
            );
        }
    }

    group.finish();
}

criterion_group!(benches, bench_bytes_to_chunks);
criterion_main!(benches);
