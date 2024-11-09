# Hash-Based Signatures in Rust

This repository contains a *prototypical* Rust implementation of hash-based one-time signatures and synchronized signatures.
The code has not been audited and is not meant to be used in production.

Note: this is work in progress and in a very early stage.

## Implemented Schemes

Currently, the following are implemented:
- Lamport (`hashsig::onetimesig::lamport`)
- Winternitz (`hashsig::onetimesig::winternitz`)
- A variant of Winternitz (`hashsig::onetimesig::permuted_winternitz`)
    * the message hash is changed before chaining is applied
    * think of it as a normalization of the message before doing Winternitz
- A variant of Winternitz (`hashsig::onetimesig::fixed_sum_winternitz`)
    * the checksum can be omitted because it is fixed
    * several seeds are tried to obtain a message hash that has this checksum

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