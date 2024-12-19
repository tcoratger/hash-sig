use crate::symmetric::message_hash::{bytes_to_chunks, MessageHash};

use super::IncomparableEncoding;



/// Incomparable Encoding Scheme based on Target Sums,
/// implemented from a given message hash.
/// CHUNK_SIZE has to be 1,2,4, or 8.
/// TARGET_SUM determines how we set the target sum,
/// and has direct impact on the signer's running time,
/// or equivalently the success probability of this encoding scheme.
/// It is recommended to set it close to the expected sum, which is:
///
///     const NUM_CHUNKS: usize = MH::OUTPUT_LENGTH * 8 / CHUNK_SIZE;
///     const MAX_CHUNK_VALUE: usize = (1 << CHUNK_SIZE) - 1;
///     const EXPECTED_SUM: usize = Self::NUM_CHUNKS * Self::MAX_CHUNK_VALUE / 2;
///
pub struct TargetSumEncoding<MH : MessageHash, const CHUNK_SIZE: usize, const TARGET_SUM: usize> {
    _marker_mh: std::marker::PhantomData<MH>,
}

impl<MH : MessageHash, const CHUNK_SIZE: usize, const TARGET_SUM: usize>
TargetSumEncoding<MH, CHUNK_SIZE, TARGET_SUM> {
    const NUM_CHUNKS: usize = MH::OUTPUT_LENGTH * 8 / CHUNK_SIZE;
    const TARGET_SUM: usize = TARGET_SUM;
}

impl<MH : MessageHash, const CHUNK_SIZE: usize, const TARGET_SUM: usize> IncomparableEncoding for TargetSumEncoding<MH, CHUNK_SIZE, TARGET_SUM> {
    type Parameter = MH::Parameter;

    type Randomness = MH::Randomness;

    const NUM_CHUNKS: usize = Self::NUM_CHUNKS;

    /// we did one experiment with random message hashes.
    /// In production, this should be estimated via more
    /// extensive experiments with concrete hash functions.
    const MAX_TRIES: usize = 5000;

    const CHUNK_SIZE: usize = CHUNK_SIZE;

    fn rand<R: rand::Rng>(rng: &mut R) -> Self::Randomness {
        MH::rand(rng)
    }

    fn encode(
        parameter: &Self::Parameter,
        message: &[u8],
        randomness: &Self::Randomness,
        epoch: u64,
    ) -> Result<Vec<u64>, super::EncodingError> {
        // apply the message hash first, get bytes
        let hash_bytes = MH::apply(parameter, epoch, randomness, message);
        // convert the bytes into chunks
        let chunks: Vec<u8> = bytes_to_chunks(&hash_bytes, Self::CHUNK_SIZE);
        let chunks_u64 : Vec<u64> = chunks.iter().map(|&x| x as u64).collect();
        let sum: u64 = chunks_u64.iter().sum();
        // only output the chunks sum to the target sum
        return if sum as usize != Self::TARGET_SUM {
            Err(())
        } else {
            Ok(chunks_u64)
        }

    }

}


// TODO: Define predefined instantiations from SHA and Poseidon