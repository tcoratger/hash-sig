# Hash-Based Signatures in Rust

This repository contains a *prototypical* Rust implementation of hash-based one-time signatures and synchronized signatures.
The code has not been audited and is not meant to be used in production.

Note: this is work in progress and in a very early stage.

## Implemented Schemes

Currently, the following are implemented:
- Lamport
- Winternitz
- A variant of Winternitz in which the message hash is changed before chaining is applied
- A variant of Witnernitz in which the checksum can be omitted because it is fixed

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