use crate::MESSAGE_LENGTH;

use super::MessageHash;

use sha2::{Digest, Sha256};

/// A message hash implemented using SHA-256
/// All lengths must be given in Bytes.
/// All lengths must be less than 255 bits.
/// Randomness length must be non-zero.
pub struct Sha256MessageHash<
    const PARAMETER_LEN: usize,
    const RAND_LEN: usize,
    const MESSAGE_HASH_LEN: usize,
>;

impl<const PARAMETER_LEN: usize, const RAND_LEN: usize, const MESSAGE_HASH_LEN: usize> MessageHash
    for Sha256MessageHash<PARAMETER_LEN, RAND_LEN, MESSAGE_HASH_LEN>
{
    type Parameter = [u8; PARAMETER_LEN];

    type Randomness = [u8; RAND_LEN];

    const OUTPUT_LENGTH: usize = MESSAGE_HASH_LEN;

    fn rand<R: rand::Rng>(rng: &mut R) -> Self::Randomness {
        let mut rand = [0u8; RAND_LEN];
        rng.fill_bytes(&mut rand);
        rand
    }

    fn apply(
        parameter: &Self::Parameter,
        epoch: u64,
        randomness: &Self::Randomness,
        message: &[u8; MESSAGE_LENGTH],
    ) -> Vec<u8> {
        assert!(
            PARAMETER_LEN < 256 / 8,
            "SHA256-Message Hash: Parameter Length must be less than 256 bit"
        );
        assert!(
            RAND_LEN < 256 / 8,
            "SHA256-Message Hash: Randomness Length must be less than 256 bit"
        );
        assert!(
            RAND_LEN > 0,
            "SHA256-Message Hash: Randomness Length must be non-zero"
        );
        assert!(
            MESSAGE_HASH_LEN < 256 / 8,
            "SHA256-Message Hash: Hash Length must be less than 256 bit"
        );

        let mut hasher = Sha256::new();

        // first add the lengths of parameters, the epoch, and randomness
        // we assume they only use 8 bits = 1 Byte
        let par_len: u8 = PARAMETER_LEN.to_le_bytes()[0];
        let epoch_len: u8 = 1;
        let rand_len = RAND_LEN.to_le_bytes()[0];
        hasher.update(&[par_len]);
        hasher.update(&[epoch_len]);
        hasher.update(&[rand_len]);

        // now add the parameter, epoch, and randomness
        hasher.update(parameter);
        hasher.update(epoch.to_le_bytes());
        hasher.update(randomness);

        // now add the actual message to be hashed
        hasher.update(message);

        // finalize the hash, and take as many bytes as we need
        let result = hasher.finalize();
        result[0..MESSAGE_HASH_LEN].try_into().unwrap()
    }
}

// Example instantiations
pub type Sha256MessageHash128x3 = Sha256MessageHash<16, 16, 16>;
pub type Sha256MessageHash192x3 = Sha256MessageHash<24, 24, 24>;

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};

    use crate::MESSAGE_LENGTH;

    use super::*;

    #[test]
    fn test_apply_128x3() {
        let mut rng = thread_rng();

        let mut parameter = [0u8; 16];
        rng.fill(&mut parameter);

        let mut message = [0u8; MESSAGE_LENGTH];
        rng.fill(&mut message);

        let epoch = 13;
        let randomness = Sha256MessageHash128x3::rand(&mut rng);

        Sha256MessageHash128x3::apply(&parameter, epoch, &randomness, &message);
    }

    #[test]
    fn test_apply_192x3() {
        let mut rng = thread_rng();

        let mut parameter = [0u8; 24];
        rng.fill(&mut parameter);

        let mut message = [0u8; MESSAGE_LENGTH];
        rng.fill(&mut message);

        let epoch = 13;
        let randomness = Sha256MessageHash192x3::rand(&mut rng);

        Sha256MessageHash192x3::apply(&parameter, epoch, &randomness, &message);
    }
}
