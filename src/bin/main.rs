use rand::rngs::OsRng;
use std::time::Instant;

use hashsig::{
    onetimesig::{lamport::Lamport, OneTimeSignatureScheme},
    symmetric::{hashprf::Sha256PRF, sha::Sha256Hash},
};

type LamportSha = Lamport<Sha256Hash, Sha256PRF>;

fn main() {
    let log_num_keys = 20;
    let num_keys = 1 << log_num_keys;
    let mut rng = OsRng;

    // start timing
    let start = Instant::now();

    // generate many keys
    for _ in 0..num_keys {
        let (_pk, _sk) = LamportSha::gen::<OsRng>(&mut rng);
    }

    // end timing
    let duration = start.elapsed();

    println!(
        "Generating 2^{:?} keys for Lamport took: {:?}",
        log_num_keys, duration
    );
}
