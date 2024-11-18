use crate::onetimesig::fixed_sum_winternitz::{
    domination_free_function_fixed_sum, salted_digest, SALT_BOUND,
};
use crate::onetimesig::permuted_winternitz::{apply_permutation, chunk_permutation};
use crate::onetimesig::winternitz::chain;
use crate::symmetric::{hashprf::Sha256PRF, sha::Sha256Hash};
use crate::symmetric::{OneWay, Pseudorandom};

use super::fixed_sum_winternitz::{FixedSumWinternitz, FixedSumWinternitzSignature};
use super::winternitz::{CHAIN_LENGTH, MSG_LENGTH, NUM_CHAINS_MESSAGE};
use super::OneTimeSignatureScheme;

/// FixedSumPermutedWinternitz One-time signature scheme.
/// This is a combination of FixedSumWinternitz and PermutedWinternitz.
pub struct FixedSumPermutedWinternitz<H: OneWay, PRF: Pseudorandom> {
    _marker_h: std::marker::PhantomData<H>,
    _marker_prf: std::marker::PhantomData<PRF>,
}

impl<H: OneWay, PRF: Pseudorandom> OneTimeSignatureScheme for FixedSumPermutedWinternitz<H, PRF>
where
    PRF::Output: Into<H::Domain>,
{
    type PublicKey = H::Domain;

    type SecretKey = PRF::Key;

    type Signature = FixedSumWinternitzSignature<H>;

    type Digest = [u8; MSG_LENGTH as usize];

    fn gen<R: rand::Rng>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey) {
        // key generation is as in fixed sum Winternitz
        // only signing and verification changes slighly
        FixedSumWinternitz::<H, PRF>::gen(rng)
    }

    fn rand_digest<R: rand::Rng>(rng: &mut R) -> Self::Digest {
        FixedSumWinternitz::<H, PRF>::rand_digest(rng)
    }

    fn sign(sk: &Self::SecretKey, digest: &Self::Digest) -> Self::Signature {
        // we try to find a salt for which we get the target sum, and then we
        // use Winternitz-style signing (without checksum) for that sum.
        // Note: in contrast to FixedSumWinternitz, we consider the checksum
        // of the permuted (as in PermutedWinternitz) digest here.

        // for each salt, we hash the digest and the salt to get a new digest
        for salt in 0..SALT_BOUND {
            // get the salted digest
            let salted_digest = salted_digest(digest, salt);

            // permute / normalize the salted digest as in PermutedWinternitz
            let permutation = chunk_permutation(&salted_digest);
            let normalized_salted_digest = apply_permutation(&salted_digest, &permutation);

            // now check if we reached the target sum
            let result = domination_free_function_fixed_sum(&normalized_salted_digest);
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

        // permute / normalize the salted digest as in PermutedWinternitz
        let permutation = chunk_permutation(&salted_digest);
        let normalized_salted_digest = apply_permutation(&salted_digest, &permutation);

        // in case we do not match the target sum, we MUST not accept
        let matches_target_sum = domination_free_function_fixed_sum(&normalized_salted_digest);
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

/// FixedSumPermutedWinternitz instantiated with SHA-256
pub type FixedSumPermutedWinternitzSha = FixedSumPermutedWinternitz<Sha256Hash, Sha256PRF>;

#[cfg(test)]
mod tests {
    use crate::onetimesig::test_templates::{
        _honest_signing_verification_template, _wrong_digest_verification_template,
    };

    use super::*;
    use rand::thread_rng;
    pub use sha2::{Digest, Sha256};

    #[test]
    fn honest_signing_verification() {
        _honest_signing_verification_template::<FixedSumPermutedWinternitzSha>();
    }

    #[test]
    fn wrong_digest_verification() {
        _wrong_digest_verification_template::<FixedSumPermutedWinternitzSha>();
    }

    #[test]
    fn manipulated_signature_verification() {
        let mut rng = thread_rng();
        let (pk, sk) = FixedSumPermutedWinternitzSha::gen(&mut rng);

        let message = b"Test message to sign";
        let digest = Sha256::digest(message);

        let mut signature = FixedSumPermutedWinternitzSha::sign(&sk, &digest.into());

        // Manipulate the salt by flipping bits
        signature.salt ^= 0xFF;

        let is_valid = FixedSumPermutedWinternitzSha::verify(&pk, &digest.into(), &signature);
        assert!(
            !is_valid,
            "The signature should be invalid when a byte is manipulated."
        );
    }
}
