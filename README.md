# Hash-Based Signatures in Rust

This repository contains a *prototypical* Rust implementation of hash-based one-time signatures and synchronized signatures.

Note: this is work in progress and in a very early stage.

## Implemented Schemes

Currently, the following are implemented:
- Lamport
- Winternitz
- A variant of Winternitz with minimal hashing, called *Beamy*.


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