use super::OneTimeSignatureScheme;
use crate::symmetric::OneWay;
use crate::symmetric::Pseudorandom;
use crate::symmetric::{hashprf::Sha256PRF, sha::Sha256Hash};

pub(crate) const MSG_LENGTH: u64 = 32; // 32 bytes = 256 bit
pub(crate) const WINDOW_SIZE: u64 = 2; // window size. Make sure it divides MSG_LENGTH and 8

pub(crate) const CHAIN_LENGTH: u64 = 1 << WINDOW_SIZE;
pub(crate) const NUM_CHAINS_MESSAGE: u64 = (MSG_LENGTH * 8).div_ceil(WINDOW_SIZE);
pub(crate) const MAX_VALUE_CHECKSUM: u64 = NUM_CHAINS_MESSAGE * (CHAIN_LENGTH - 1);
pub(crate) const LOG_MAX_VALUE_CHECKSUM: u64 = 63 - MAX_VALUE_CHECKSUM.leading_zeros() as u64;
pub(crate) const NUM_CHAINS_CHECKSUM: u64 = LOG_MAX_VALUE_CHECKSUM / WINDOW_SIZE + 1;
pub(crate) const NUM_CHAINS: u64 = NUM_CHAINS_MESSAGE + NUM_CHAINS_CHECKSUM;
pub(crate) const CHUNKS_PER_BYTE: u64 = 8 / WINDOW_SIZE;

/// Winternitz One-time signature scheme
pub struct Winternitz<H: OneWay, PRF: Pseudorandom> {
    _marker_h: std::marker::PhantomData<H>,
    _marker_prf: std::marker::PhantomData<PRF>,
}

/// Computes the end of a Winternitz chain given a starting point and a specified number of steps.
///
/// # Parameters
/// - `steps`: The number of steps in the chain, excluding the start.
///    For example, 2 steps from a starting point `A` would result in `A -> B -> C`.
/// - `start`: The initial value of the chain (or starting point).
///
/// # Returns
/// - The final value at the end of the chain after the given number of steps.
///
/// # Note
/// In WOTS+, this function typically incorporates domain separation and pseudorandom masking.
/// However, as this is a Proof of Concept (PoC), we omit these additional steps.
///
/// # Constraints
/// - `steps` should be less than `CHAIN_LENGTH` to avoid excessive computation.
///
/// # Panics
/// - The function panics if `steps >= CHAIN_LENGTH`.
pub(crate) fn chain<H: OneWay>(steps: usize, start: &H::Domain) -> H::Domain {
    // Ensure `steps` is within the permissible chain length.
    assert!(
        steps < CHAIN_LENGTH as usize,
        "Number of steps > CHAIN_LENGTH."
    );

    // Initialize the chain with the starting value.
    let mut current = start.clone();

    // Apply the one-way function iteratively to compute each step in the chain.
    for _ in 0..steps {
        current = H::apply(&[current]);
    }

    // Return the final value at the end of the chain.
    current
}

/// Isolates a chunk of bits from a byte based on the specified chunk index and window size.
///
/// This function takes a byte and extracts a specified chunk of bits, where the chunk's
/// position is determined by the `chunk_index` and the size of the chunk is defined
/// by `window_size`. It is assumed that `window_size` divides 8 and is between 1 and 8.
///
/// # Parameters
/// - `byte`: The byte from which to isolate the chunk.
/// - `chunk_index`: The index of the chunk to extract. The index is zero-based.
/// - `window_size`: The size of the chunk in bits. Must be a divisor of 8 and within the range [1, 8].
///
/// # Returns
/// Returns a `u8` containing the isolated chunk of bits. The chunk is right-aligned in the byte.
///
/// # Panics
/// Panics if `window_size` is not between 1 and 8 or if it does not evenly divide 8.
/// Panics if `chunk_index` is not within bounds, i.e., if it is at least 8 / window_size.
pub(crate) fn isolate_w_bit_chunk(byte: u8, chunk_index: usize, window_size: usize) -> u8 {
    // Ensure window divides 8 and is between 1 and 8
    assert!(window_size > 0 && window_size <= 8 && 8 % window_size == 0);

    // Ensure the chunk index is within bounds
    assert!(chunk_index < 8 / window_size);

    // Calculate the start bit position of the i-th chunk
    let start_bit_pos = chunk_index * window_size;

    // Create a bitmask for window_size many bits
    let mask = (1u8 << window_size) - 1;

    // Shift the byte right and apply the mask
    (byte >> start_bit_pos) & mask
}

/// Implements a domination-free function for the Winternitz scheme.
///
/// This function generates a sequence of integers representing how far we will walk
/// during signing in the hash chains. It computes the steps from the provided message digest,
/// as well as a checksum calculated on-the-fly.
///
/// # Parameters
/// - `digest`: A reference to a byte array representing the message digest. The size of the
///   array must be equal to `MSG_LENGTH`.
///
/// # Returns
/// Returns an array of `usize` representing the steps for each chain.
///
/// # Panics
/// This function may panic if the calculations for the indices exceed the bounds of the arrays
/// or if constants such as `MSG_LENGTH`, `NUM_CHAINS`, and `NUM_CHAINS_CHECKSUM` are not defined
/// correctly to accommodate the size of the arrays. Otherwise, the function does not panic.
fn domination_free_function(digest: &[u8; MSG_LENGTH as usize]) -> [usize; NUM_CHAINS as usize] {
    let mut steps = [0; NUM_CHAINS as usize];

    // first, for the message part
    // note: we also determine the checksum on the fly
    let mut checksum = 0u64;

    for i in 0..NUM_CHAINS_MESSAGE as usize {
        // isolate the byte in which the chunk resides
        let byte_index = i / CHUNKS_PER_BYTE as usize;
        let byte = digest[byte_index];

        // isolate the chunk
        let chunk_index = i % CHUNKS_PER_BYTE as usize;
        steps[i] = isolate_w_bit_chunk(byte, chunk_index, WINDOW_SIZE as usize) as usize;

        // update the checksum
        checksum += CHAIN_LENGTH - 1 - steps[i] as u64;
    }

    // fill the steps related to the checksum
    let checksum_bytes = checksum.to_le_bytes();
    for i in 0..NUM_CHAINS_CHECKSUM as usize {
        // isolate the byte in which the chunk resides
        let byte_index = i / CHUNKS_PER_BYTE as usize;
        let byte = checksum_bytes[byte_index];

        // isolate the chunk
        let chunk_index = i % CHUNKS_PER_BYTE as usize;
        steps[NUM_CHAINS_MESSAGE as usize + i] =
            isolate_w_bit_chunk(byte, chunk_index, WINDOW_SIZE as usize) as usize;
    }

    steps
}

impl<H: OneWay, PRF: Pseudorandom> OneTimeSignatureScheme for Winternitz<H, PRF>
where
    PRF::Output: Into<H::Domain>,
{
    type PublicKey = H::Domain;

    type SecretKey = PRF::Key;

    type Signature = [H::Domain; NUM_CHAINS as usize];

    type Digest = [u8; MSG_LENGTH as usize];

    fn gen<R: rand::Rng>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey) {
        // use a PRF key as the secret key
        let sk = PRF::gen(rng);

        // expand the secret key to NUM_CHAINS many chain starting points
        let chain_starts: [H::Domain; NUM_CHAINS as usize] =
            std::array::from_fn(|i| PRF::apply(&sk, i as u64).into());

        // compute the end of each chain
        let mut chain_ends: [<H as OneWay>::Domain; NUM_CHAINS as usize] =
            [H::Domain::default(); NUM_CHAINS as usize];
        for (i, &start) in chain_starts.iter().enumerate() {
            chain_ends[i] = chain::<H>(CHAIN_LENGTH as usize - 1, &start);
        }

        // hash them all to get the pk
        let pk = H::apply(&chain_ends);

        (pk, sk)
    }

    fn sign(sk: &Self::SecretKey, digest: &Self::Digest) -> Self::Signature {
        // expand the secret key to NUM_CHAINS many chain starting points
        let chain_starts: [H::Domain; NUM_CHAINS as usize] =
            std::array::from_fn(|i| PRF::apply(&sk, i as u64).into());

        // determine how far we will walk with our chains
        let steps: [usize; NUM_CHAINS as usize] = domination_free_function(digest);

        // now, partially walk the chain to get the signature
        let mut signature: [<H as OneWay>::Domain; NUM_CHAINS as usize] =
            [H::Domain::default(); NUM_CHAINS as usize];
        for (i, &start) in chain_starts.iter().enumerate() {
            signature[i] = chain::<H>(steps[i], &start);
        }

        signature
    }

    fn verify(pk: &Self::PublicKey, digest: &Self::Digest, sig: &Self::Signature) -> bool {
        // determine how far the signer had to walk
        let steps_sign: [usize; NUM_CHAINS as usize] = domination_free_function(digest);

        // if the signer already walked k steps, then we need to walk CHAIN_LENGTH - 1 - k steps
        let steps_verify: [usize; NUM_CHAINS as usize] =
            std::array::from_fn(|i| CHAIN_LENGTH as usize - 1 - steps_sign[i]);

        // continue walking the chains to compute the ends of all chains
        let mut chain_ends: [<H as OneWay>::Domain; NUM_CHAINS as usize] =
            [H::Domain::default(); NUM_CHAINS as usize];
        for (i, &intermediate) in sig.iter().enumerate() {
            chain_ends[i] = chain::<H>(steps_verify[i], &intermediate);
        }

        // check that the hash of these chain ends matches the pk
        *pk == H::apply(&chain_ends)
    }

    fn is_digest_valid(_digest: &Self::Digest) -> bool {
        // every digest can be signed in this scheme
        true
    }
}

/// Winternitz instantiated with SHA-256
pub type WinternitzSha = Winternitz<Sha256Hash, Sha256PRF>;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    pub use sha2::{Digest, Sha256};

    #[test]
    fn honest_signing_verification() {
        let mut rng = thread_rng();
        let (pk, sk) = WinternitzSha::gen(&mut rng);

        let message = b"Test message to sign";
        let digest = Sha256::digest(message);

        let signature = WinternitzSha::sign(&sk, &digest.into());

        let is_valid = WinternitzSha::verify(&pk, &digest.into(), &signature);
        assert!(
            is_valid,
            "The signature should be valid with correct keys and message."
        );
    }

    #[test]
    fn manipulated_signature_verification() {
        let mut rng = thread_rng();
        let (pk, sk) = WinternitzSha::gen(&mut rng);

        let message = b"Test message to sign";
        let digest = Sha256::digest(message);

        let mut signature = WinternitzSha::sign(&sk, &digest.into());

        // Manipulate one byte in the signature's opened field
        signature[0][0] ^= 0xFF; // Flip all bits in the first byte of the first element

        let is_valid = WinternitzSha::verify(&pk, &digest.into(), &signature);
        assert!(
            !is_valid,
            "The signature should be invalid when a byte is manipulated."
        );
    }

    #[test]
    fn test_isolate_w_bit_chunk() {
        // In this test, we check that `isolate_w_bit_chunk` panics as expected

        let byte: u8 = 0b01101100;

        assert_eq!(isolate_w_bit_chunk(byte, 0, 2), 0b00);
        assert_eq!(isolate_w_bit_chunk(byte, 1, 2), 0b11);
        assert_eq!(isolate_w_bit_chunk(byte, 2, 2), 0b10);
        assert_eq!(isolate_w_bit_chunk(byte, 3, 2), 0b01);

        assert_eq!(isolate_w_bit_chunk(byte, 0, 4), 0b1100);
        assert_eq!(isolate_w_bit_chunk(byte, 1, 4), 0b0110);
    }

    #[test]
    fn test_chain_associative() {
        // We test that the function chain is associative, i.e.,
        // that running a chain of length k2 starting from the end
        // of a chain of length k1 is the same as running a chain
        // of length k1 + k2 directly from the starting point.
        let mut rng = thread_rng();
        let start = Sha256Hash::sample(&mut rng);

        let k1 = 1;
        let k2 = 2;

        // run a chain of length k1
        let middle = chain::<Sha256Hash>(k1, &start);
        // run a chain of length k2 starting from middle
        let end_one = chain::<Sha256Hash>(k2, &middle);

        // run the entire chain directly
        let end_two = chain::<Sha256Hash>(k1 + k2, &start);

        // the two ends should be the same
        assert_eq!(end_one, end_two);
    }
}
