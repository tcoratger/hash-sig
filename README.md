# Hash-Based Signatures in Rust

This repository contains a *prototypical* Rust implementation of (synchronized) signatures based on tweakable hash functions and incomparable encodings.
The code has not been audited and is not meant to be used in production. It is a playground to explore and benchmark these signatures.

## Tests

Run the tests with

```
cargo test
```

## Benchmarks

Benchmarks are provided using criterion. They take a while, as key generation is expensive, and as a large number of schemes are benchmarked.
Run them with

```
cargo bench
```

The schemes that are benchmarked are hardcoded instantiations of the generic framework, which are defined in `hashsig::signature::generalized_xmss::instantiations_sha`.
The parameters of these instantiations have been chosen carefully with the aim to achieve a desired security level.

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