use crate::symmetric::{hashprf::Sha256PRF, sha::Sha256Hash, OneWay, Pseudorandom};
use sha2::{Digest, Sha256};

use super::{
    winternitz::{
        chain, isolate_w_bit_chunk, CHAIN_LENGTH, CHUNKS_PER_BYTE, MSG_LENGTH, NUM_CHAINS_MESSAGE,
        WINDOW_SIZE,
    },
    OneTimeSignatureScheme,
};

/// We take for the target sum the expected sum, assuming hashes are fully random.
/// Let X_i be the i-th chunk. Then, Expect[X_i] = (CHAIN_LENGTH - 1)/2
/// and Expect[Sum_i X_i] = Sum_i Expect[X_i] = NUM_CHAINS_MESSAGE * (CHAIN_LENGTH - 1)/2
pub(crate) const TARGET_SUM: u64 = NUM_CHAINS_MESSAGE * (CHAIN_LENGTH - 1) / 2;
pub(crate) const SALT_BOUND: u32 = 1 << 16; // 16 bit salts

/// FixedSumWinternitz One-time signature scheme,
/// called WOTS+C in https://eprint.iacr.org/2022/778
pub struct FixedSumWinternitz<H: OneWay, PRF: Pseudorandom> {
    _marker_h: std::marker::PhantomData<H>,
    _marker_prf: std::marker::PhantomData<PRF>,
}

pub struct FixedSumWinternitzSignature<H: OneWay> {
    signature: [H::Domain; NUM_CHAINS_MESSAGE as usize],
    salt: u32,
}

/// Implements a domination-free function for the FixedSumWinternitz scheme.
///
/// This function generates a sequence of integers representing how far we will walk
/// during signing in the hash chains. It computes the steps from the provided message digest.
/// Importantly, this function is only domination-free if we assume a fixed sum of the steps.
/// To this end, the function returns an error if the sum does not match the target sum.
///
/// # Parameters
/// - `digest`: A reference to a byte array representing the message digest. The size of the
///   array must be equal to `MSG_LENGTH`.
///
/// # Returns
/// Returns `Ok([usize; NUM_CHAINS_MESSAGE])` containing the steps for each chain if the sum
/// of the steps matches the predefined `TARGET_SUM`. Otherwise, returns `Err("Sum mismatch")`
/// indicating that the computed steps do not meet the required fixed sum.
///
/// # Errors
/// This function returns an `Err` if the sum of the generated steps does not match `TARGET_SUM`.
///
/// # Panics
/// This function may panic if the calculations for the indices exceed the bounds of the arrays
/// or if constants such as `MSG_LENGTH`, `NUM_CHAINS_MESSAGE` are not defined
/// correctly to accommodate the size of the arrays. Otherwise, the function does not panic.
fn domination_free_function_fixed_sum(
    digest: &[u8; MSG_LENGTH as usize],
) -> Result<[usize; NUM_CHAINS_MESSAGE as usize], &'static str> {
    let mut steps = [0; NUM_CHAINS_MESSAGE as usize];

    for i in 0..NUM_CHAINS_MESSAGE as usize {
        // Isolate the byte in which the chunk resides
        let byte_index = i / CHUNKS_PER_BYTE as usize;
        let byte = digest[byte_index];

        // Isolate the chunk
        let chunk_index = i % CHUNKS_PER_BYTE as usize;
        steps[i] = isolate_w_bit_chunk(byte, chunk_index, WINDOW_SIZE as usize) as usize;
    }

    // Calculate the sum of the steps array
    let sum: usize = steps.iter().sum();

    // Check if the sum matches the target
    if sum as u64 == TARGET_SUM {
        Ok(steps)
    } else {
        Err("Sum mismatch")
    }
}

/// Computes a salted digest by hashing the provided digest and salt with SHA-256,
/// then truncates the result to a fixed length.
///
/// This function takes a `digest` (byte array) and a `salt` (32-bit integer),
/// hashes their concatenation using the SHA-256 algorithm, and then truncates
/// the resulting 32-byte hash to the length specified by `MSG_LENGTH`.
///
/// # Parameters
/// - `digest`: A reference to a byte array representing the initial digest. The size
///   of this array must be exactly `MSG_LENGTH`.
/// - `salt`: A 32-bit unsigned integer used to further randomize the digest,
///   which is appended in big-endian format to the `digest` before hashing.
///
/// # Returns
/// Returns a fixed-size byte array of length `MSG_LENGTH`, which is the truncated
/// SHA-256 hash of the concatenated `digest` and `salt`.
///
/// # Panics
/// This function will panic if `MSG_LENGTH` is greater than 32, as the SHA-256 hash
/// output is only 32 bytes long.
fn salted_digest(digest: &[u8; MSG_LENGTH as usize], salt: u32) -> [u8; MSG_LENGTH as usize] {
    // hash the digest and the salt
    let mut hasher = Sha256::new();
    hasher.update(digest);
    hasher.update(&salt.to_be_bytes());
    let full_hash = hasher.finalize();
    let mut salted_digest = [0u8; MSG_LENGTH as usize];
    salted_digest.copy_from_slice(&full_hash[..MSG_LENGTH as usize]);
    salted_digest
}

impl<H: OneWay, PRF: Pseudorandom> OneTimeSignatureScheme for FixedSumWinternitz<H, PRF>
where
    PRF::Output: Into<H::Domain>,
{
    type PublicKey = H::Domain;

    type SecretKey = PRF::Key;

    type Signature = FixedSumWinternitzSignature<H>;

    type Digest = [u8; MSG_LENGTH as usize];

    fn gen<R: rand::Rng>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey) {
        // use a PRF key as the secret key
        let sk = PRF::gen(rng);

        // expand the secret key to NUM_CHAINS_MESSAGE many chain starting points
        // Note: in contrast to plain Winternitz, we will not need the checksum part.
        let chain_starts: [H::Domain; NUM_CHAINS_MESSAGE as usize] =
            std::array::from_fn(|i| PRF::apply(&sk, i as u64).into());

        // compute the end of each chain
        let mut chain_ends: [<H as OneWay>::Domain; NUM_CHAINS_MESSAGE as usize] =
            [H::Domain::default(); NUM_CHAINS_MESSAGE as usize];
        for (i, &start) in chain_starts.iter().enumerate() {
            chain_ends[i] = chain::<H>(CHAIN_LENGTH as usize - 1, &start);
        }

        // hash them all to get the pk
        let pk = H::apply(&chain_ends);

        (pk, sk)
    }

    fn rand_digest<R: rand::Rng>(rng: &mut R) -> Self::Digest {
        let mut digest = [0u8; MSG_LENGTH as usize];
        rng.fill_bytes(&mut digest);
        digest
    }

    fn sign(sk: &Self::SecretKey, digest: &Self::Digest) -> Self::Signature {

        // we try to find a salt for which we get the target sum, and then we
        // use Winternitz-style signing (without checksum) for that sum.

        // for each salt, we hash the digest and the salt to get a new digest
        for salt in 0..SALT_BOUND {
            // get the salted digest
            let salted_digest = salted_digest(digest, salt);

            // now check if we reached the target sum
            let result = domination_free_function_fixed_sum(&salted_digest);
            if let Ok(steps) = result {
                // we have reached the target sum, so let's create a signature

                // first, expand the secret key to NUM_CHAINS_MESSAGE many chain starting points
                let chain_starts: [H::Domain; NUM_CHAINS_MESSAGE as usize] =
                    std::array::from_fn(|i| PRF::apply(&sk, i as u64).into());

                // then, create the actual signature part by walking the chains according to the steps
                let mut signature: [<H as OneWay>::Domain; NUM_CHAINS_MESSAGE as usize] =
                    [H::Domain::default(); NUM_CHAINS_MESSAGE as usize];
                for (i, &start) in chain_starts.iter().enumerate() {
                    signature[i] = chain::<H>(steps[i], &start);
                }

                // Finally, include the actual signature and the salt to get the complete signature
                return FixedSumWinternitzSignature { signature, salt };
            }
        }

        // We did not find a valid salt, so we can't generate a signature.
        panic!("Did not find a valid salt.");
    }

    fn verify(pk: &Self::PublicKey, digest: &Self::Digest, sig: &Self::Signature) -> bool {

        // the salt MUST be in range
        if sig.salt >= SALT_BOUND {
            return false;
        }

        // recompute the salted digest
        let salted_digest = salted_digest(digest, sig.salt);

        // in case we do not match the target sum, we MUST not accept
        let matches_target_sum = domination_free_function_fixed_sum(&salted_digest);
        match matches_target_sum {
            Ok(steps_sign) => {
                // now we know that we match the target sum,
                // so verify as in Winternitz by walking the chains

                // if the signer already walked k steps, then we need to walk CHAIN_LENGTH - 1 - k steps
                let steps_verify: [usize; NUM_CHAINS_MESSAGE as usize] =
                    std::array::from_fn(|i| CHAIN_LENGTH as usize - 1 - steps_sign[i]);

                // continue walking the chains to compute the ends of all chains
                let mut chain_ends: [<H as OneWay>::Domain; NUM_CHAINS_MESSAGE as usize] =
                    [H::Domain::default(); NUM_CHAINS_MESSAGE as usize];
                for (i, &intermediate) in sig.signature.iter().enumerate() {
                    chain_ends[i] = chain::<H>(steps_verify[i], &intermediate);
                }

                // check that the hash of these chain ends matches the pk
                *pk == H::apply(&chain_ends)
            }
            Err(_) => false,
        }
    }
}

/// FixedSumWinternitz instantiated with SHA-256
pub type FixedSumWinternitzSha = FixedSumWinternitz<Sha256Hash, Sha256PRF>;

#[cfg(test)]
mod tests {
    use crate::onetimesig::test_templates::{_honest_signing_verification_template, _wrong_digest_verification_template};

    use super::*;
    use rand::thread_rng;
    pub use sha2::{Digest, Sha256};

    #[test]
    fn honest_signing_verification() {
        _honest_signing_verification_template::<FixedSumWinternitzSha>();
    }

    #[test]
    fn wrong_digest_verification() {
        _wrong_digest_verification_template::<FixedSumWinternitzSha>();
    }

    #[test]
    fn manipulated_signature_verification() {
        let mut rng = thread_rng();
        let (pk, sk) = FixedSumWinternitzSha::gen(&mut rng);

        let message = b"Test message to sign";
        let digest = Sha256::digest(message);

        let mut signature = FixedSumWinternitzSha::sign(&sk, &digest.into());

        // Manipulate the salt by flipping bits
        signature.salt ^= 0xFF;

        let is_valid = FixedSumWinternitzSha::verify(&pk, &digest.into(), &signature);
        assert!(
            !is_valid,
            "The signature should be invalid when a byte is manipulated."
        );
    }
}
