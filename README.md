# Hash-Based Signatures in Rust

This repository contains a *prototypical* Rust implementation of (synchronized) signatures based on tweakable hash functions and incomparable encodings.
The code has not been audited and is not meant to be used in production. It is a playground to explore and benchmark these signatures.

## Tests

Run the tests with

```
cargo test
```

## Benchmarks

Benchmarks are provided using criterion. Run them with

```
cargo bench
```

## License

Apache Version 2.0.