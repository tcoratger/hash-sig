# Hash-Based Signatures in Rust

This repository contains a *prototypical* Rust implementation of (synchronized) signatures based on tweakable hash functions and incomparable encodings.
The code has not been audited and is not meant to be used in production. It is a playground to explore and benchmark these signatures. Use it at your own risk.

## Tests

Run the tests with

```
cargo test
```

By default, this will exclude some of the tests. In particular, correctness tests for real instantiations take quite long and are excluded.
If you want to run *all* tests, you can use

```
cargo test --release --features slow-tests
```

Removing the `--release` is also an option but tests will take even longer.

## Benchmarks

Benchmarks are provided using criterion.
They take a while, as key generation is expensive, and as a large number of schemes are benchmarked.
Run them with

```
cargo bench
```

The schemes that are benchmarked are hardcoded instantiations of the generic framework, which are defined in `hashsig::signature::generalized_xmss`.
The parameters of these instantiations have been chosen carefully with the aim to achieve a desired security level.
By default, key generation is not benchmarked. There are two options to benchmark it:
1. add the option `--features with-gen-benches-sha` or `--features with-gen-benches-poseidon` to `cargo bench`. Note that this will make benchmarks very slow, as key generation will be repeated within the benchmarks. Especially for Poseidon, this is not recommended.
2. use code similar to the one provided in `src/bin/main.rs` and run it with `cargo run --release`.

If criterion only generates json files, one way to extract all means for all benchmarks easily (without re-running criterion) is to run

```
python3 benchmark-mean.py target
```

Confidence intervals can also be shown via

```
python3 benchmark-mean.py target --intervals
```

## License

Apache Version 2.0.