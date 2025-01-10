use super::Pseudorandom;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};

use num_bigint::BigUint;
use zkhash::ark_ff::MontConfig;
use zkhash::fields::babybear::{FpBabyBear, FqConfig};

type F = FpBabyBear;

// Number of pseudorandom bytes to generate one pseudorandom field element
const PRF_BYTES_PER_FE: usize = 8;

const KEY_LENGTH: usize = 32; // 32 bytes
const PRF_DOMAIN_SEP: [u8; 16] = [
    0xae, 0xae, 0x22, 0xff, 0x00, 0x01, 0xfa, 0xff, 0x21, 0xaf, 0x12, 0x00, 0x01, 0x11, 0xff, 0x00,
];

/// A pseudorandom function mapping to field elements.
/// It is implemented using Shake128.
/// It outputs OUTPUT_LENGTH_FE many field elements.
pub struct ShakePRFtoF<const OUTPUT_LENGTH_FE: usize>;

impl<const OUTPUT_LENGTH_FE: usize> Pseudorandom for ShakePRFtoF<OUTPUT_LENGTH_FE> {
    type Key = [u8; KEY_LENGTH];
    type Output = [F; OUTPUT_LENGTH_FE];

    fn gen<R: rand::Rng>(rng: &mut R) -> Self::Key {
        let mut key = [0u8; KEY_LENGTH];
        rng.fill(&mut key);
        key
    }

    fn apply(key: &Self::Key, epoch: u32, index: u64) -> Self::Output {
        // Create a new SHAKE128 instance
        let mut hasher = Shake128::default();

        // Hash the domain separator
        hasher.update(&PRF_DOMAIN_SEP);

        // Hash the key
        hasher.update(key);

        // Hash the epoch
        hasher.update(&epoch.to_be_bytes());

        // Hash the index
        hasher.update(&index.to_be_bytes());

        // Finalize the hash process and create an XofReader
        let mut xof_reader = hasher.finalize_xof();

        // Buffer to store the output
        let mut prf_output = vec![0u8; PRF_BYTES_PER_FE * OUTPUT_LENGTH_FE];

        // Read the extended output into the buffer
        xof_reader.read(&mut prf_output);

        // Final result
        let mut result = Vec::new();

        // Mapping bytes to field elements
        for chunk in prf_output.chunks(PRF_BYTES_PER_FE) {
            let integer_value = BigUint::from_bytes_be(chunk) % BigUint::from(FqConfig::MODULUS);
            result.push(F::from(integer_value));
        }
        let slice = &result[0..OUTPUT_LENGTH_FE];
        slice.try_into().expect("Length mismatch")
    }

    #[cfg(test)]
    fn internal_consistency_check() {
        // No check is needed
    }
}
