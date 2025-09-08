use rand::Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{
    MESSAGE_LENGTH,
    inc_encoding::IncomparableEncoding,
    symmetric::{
        prf::Pseudorandom,
        tweak_hash::{TweakableHash, chain},
        tweak_hash_tree::{HashTree, HashTreeOpening, hash_tree_verify},
    },
};

use super::{SignatureScheme, SigningError};

/// Implementation of the generalized XMSS signature scheme
/// from any incomparable encoding scheme and any tweakable hash
///
/// It also uses a PRF for key generation, and one has to specify
/// the (base 2 log of the) key lifetime.
///
/// Note: lifetimes beyond 2^32 are not supported.
pub struct GeneralizedXMSSSignatureScheme<
    PRF: Pseudorandom,
    IE: IncomparableEncoding,
    TH: TweakableHash,
    const LOG_LIFETIME: usize,
> {
    _prf: std::marker::PhantomData<PRF>,
    _ie: std::marker::PhantomData<IE>,
    _th: std::marker::PhantomData<TH>,
}

/// Signature for GeneralizedXMSSSignatureScheme
/// It contains a Merkle authentication path, encoding randomness, and a list of hashes
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct GeneralizedXMSSSignature<IE: IncomparableEncoding, TH: TweakableHash> {
    path: HashTreeOpening<TH>,
    rho: IE::Randomness,
    hashes: Vec<TH::Domain>,
}

/// Public key for GeneralizedXMSSSignatureScheme
/// It contains a Merkle root and a parameter for the tweakable hash
#[derive(Serialize, Deserialize)]
pub struct GeneralizedXMSSPublicKey<TH: TweakableHash> {
    root: TH::Domain,
    parameter: TH::Parameter,
}

/// Secret key for GeneralizedXMSSSignatureScheme
/// It contains a PRF key and a Merkle tree.
///
/// Note: one may choose to regenerate the tree on the fly, but this
/// would be costly for signatures.
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct GeneralizedXMSSSecretKey<PRF: Pseudorandom, TH: TweakableHash> {
    prf_key: PRF::Key,
    tree: HashTree<TH>,
    parameter: TH::Parameter,
    activation_epoch: usize,
    num_active_epochs: usize,
}

impl<PRF: Pseudorandom, IE: IncomparableEncoding, TH: TweakableHash, const LOG_LIFETIME: usize>
    SignatureScheme for GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>
where
    PRF::Output: Into<TH::Domain>,
    TH::Parameter: Into<IE::Parameter>,
{
    type PublicKey = GeneralizedXMSSPublicKey<TH>;

    type SecretKey = GeneralizedXMSSSecretKey<PRF, TH>;

    type Signature = GeneralizedXMSSSignature<IE, TH>;

    const LIFETIME: u64 = 1 << LOG_LIFETIME;

    fn key_gen<R: Rng>(
        rng: &mut R,
        activation_epoch: usize,
        num_active_epochs: usize,
    ) -> (Self::PublicKey, Self::SecretKey) {
        // checks for `activation_epoch` and `num_active_epochs`
        assert!(
            activation_epoch + num_active_epochs <= Self::LIFETIME as usize,
            "Key gen: `activation_epoch` and `num_active_epochs` are invalid for this lifetime"
        );

        // Note: this implementation first generates all one-time sk's
        // and one-time pk's and then computes a Merkle tree in one go.
        // For a large lifetime (e.g., L = 2^32), this approach is not
        // well  suited  when  running on, say, 16 GiB of RAM. In this
        // setting, a more sophisticated approach is needed, e.g., one
        // could first  compute half (or quarter) of  one-time sk/pk's
        // and then their root, then save them to disc,  continue with
        // the second half, and then combine both.

        // we need a random parameter to be used for the tweakable hash
        let parameter = TH::rand_parameter(rng);

        // we need a PRF key to generate our list of actual secret keys
        let prf_key = PRF::key_gen(rng);

        // for each epoch, generate the secret key for the epoch, where
        // an epoch secret key is a list of domain elements derived from the
        // pseudorandom function.
        // We have one such element per chain, and we have one
        // chain per chunk of the codeword. In the same go, we also generate
        // the respective public key, which is obtained by walking the hash
        // chain starting at the secret key element.
        // The public key for that epoch is then the hash of all chain ends.

        let num_chains = IE::DIMENSION;
        let chain_length = IE::BASE;

        // parallelize the chain ends hash computation for each epoch
        let activation_range = activation_epoch..activation_epoch + num_active_epochs;
        let chain_ends_hashes = activation_range
            .into_par_iter()
            .map(|epoch| {
                // each epoch has a number of chains
                // parallelize the chain ends computation for each chain
                let chain_ends = (0..num_chains)
                    .into_par_iter()
                    .map(|chain_index| {
                        // each chain start is just a PRF evaluation
                        let start = PRF::apply(&prf_key, epoch as u32, chain_index as u64).into();
                        // walk the chain to get the public chain end
                        chain::<TH>(
                            &parameter,
                            epoch as u32,
                            chain_index as u8,
                            0,
                            chain_length - 1,
                            &start,
                        )
                    })
                    .collect::<Vec<_>>();
                // build hash of chain ends / public keys
                TH::apply(&parameter, &TH::tree_tweak(0, epoch as u32), &chain_ends)
            })
            .collect::<Vec<_>>();

        // now build a Merkle tree on top of the hashes of chain ends / public keys
        let tree = HashTree::new(
            rng,
            LOG_LIFETIME,
            activation_epoch,
            &parameter,
            chain_ends_hashes,
        );
        let root = tree.root();

        // assemble public key and secret key
        let pk = GeneralizedXMSSPublicKey { root, parameter };
        let sk = GeneralizedXMSSSecretKey {
            prf_key,
            tree,
            parameter,
            activation_epoch,
            num_active_epochs,
        };

        (pk, sk)
    }

    fn sign<R: Rng>(
        rng: &mut R,
        sk: &Self::SecretKey,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
    ) -> Result<Self::Signature, SigningError> {
        // check that epoch is indeed a valid epoch in the activation range
        let activation_range = sk.activation_epoch..sk.activation_epoch + sk.num_active_epochs;
        assert!(
            activation_range.contains(&(epoch as usize)),
            "Signing: key not active during this epoch"
        );

        // first component of the signature is the Merkle path that
        // opens the one-time pk for that epoch, where the one-time pk
        // will be recomputed by the verifier from the signature.
        let path = sk.tree.path(epoch);

        // now, we need to encode our message using the incomparable encoding.
        // we retry until we get a valid codeword, or until we give up.
        let max_tries = IE::MAX_TRIES;
        let mut attempts = 0;
        let mut x = None;
        let mut rho = None;
        while attempts < max_tries {
            // sample a randomness and try to encode the message
            let curr_rho = IE::rand(rng);
            let curr_x = IE::encode(&sk.parameter.into(), message, &curr_rho, epoch);

            // check if we have found a valid codeword, and if so, stop searching
            if curr_x.is_ok() {
                rho = Some(curr_rho);
                x = curr_x.ok();
                break;
            }

            attempts += 1;
        }

        // if we have not found a valid codeword, return an error
        if x.is_none() {
            return Err(SigningError::EncodingAttemptsExceeded {
                attempts: max_tries,
            });
        }

        // otherwise, unwrap x and rho
        let x = x.unwrap();
        let rho = rho.unwrap();

        // we will include rho in the signature, and
        // we use x to determine how far the signer walks in the chains
        let num_chains = IE::DIMENSION;
        assert!(
            x.len() == num_chains,
            "Encoding is broken: returned too many or too few chunks."
        );

        // In parallel, compute the hash values for each chain based on the codeword `x`.
        let hashes = (0..num_chains)
            .into_par_iter()
            .map(|chain_index| {
                // get back to the start of the chain from the PRF
                let start = PRF::apply(&sk.prf_key, epoch, chain_index as u64).into();
                // now walk the chain for a number of steps determined by the current chunk of x
                let steps = x[chain_index] as usize;
                chain::<TH>(&sk.parameter, epoch, chain_index as u8, 0, steps, &start)
            })
            .collect();

        // assemble the signature: Merkle path, randomness, chain elements
        Ok(GeneralizedXMSSSignature { path, rho, hashes })
    }

    fn verify(
        pk: &Self::PublicKey,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
        sig: &Self::Signature,
    ) -> bool {
        assert!(
            (epoch as u64) < Self::LIFETIME,
            "Generalized XMSS - Verify: Epoch too large."
        );

        // first get back the codeword and make sure
        // encoding succeeded with the given randomness.
        let x = IE::encode(&pk.parameter.into(), message, &sig.rho, epoch);
        if x.is_err() {
            return false;
        }
        let x = x.unwrap();

        // now, we recompute the epoch's one-time public key
        // from the hashes by walking hash chains.
        let chain_length = IE::BASE;
        let num_chains = IE::DIMENSION;
        assert!(
            x.len() == num_chains,
            "Encoding is broken: returned too many or too few chunks."
        );
        let mut chain_ends = Vec::with_capacity(num_chains);
        for (chain_index, xi) in x.iter().enumerate() {
            // If the signer has already walked x[i] steps, then we need
            // to walk chain_length - 1 - x[i] steps to reach the end of the chain
            // Note: by our consistency checks, we have chain_length <= 2^8, so chain_length - 1 fits into u8
            let steps = (chain_length - 1) as u8 - xi;
            let start_pos_in_chain = *xi;
            let start = &sig.hashes[chain_index];
            let end = chain::<TH>(
                &pk.parameter,
                epoch,
                chain_index as u8,
                start_pos_in_chain,
                steps as usize,
                start,
            );
            chain_ends.push(end);
        }

        // this set of chain ends should be a leaf in the Merkle tree
        // we verify that by checking the Merkle authentication path
        hash_tree_verify(
            &pk.parameter,
            &pk.root,
            epoch,
            chain_ends.as_slice(),
            &sig.path,
        )
    }

    #[cfg(test)]
    fn internal_consistency_check() {
        // we check consistency of all internally used components
        // namely, PRF, incomparable encoding, and tweak hash
        PRF::internal_consistency_check();
        IE::internal_consistency_check();
        TH::internal_consistency_check();

        // assert BASE and DIMENSION are small enough to make sure that we can fit
        // pos_in_chain and chain_index in u8.

        assert!(
            IE::BASE <= 1 << 8,
            "Generalized XMSS: Encoding base too large, must be at most 2^8"
        );
        assert!(
            IE::DIMENSION <= 1 << 8,
            "Generalized XMSS: Encoding dimension too large, must be at most 2^8"
        );
    }
}

/// Instantiations of the generalized XMSS signature scheme based on Poseidon2
pub mod instantiations_poseidon;
/// Instantiations of the generalized XMSS signature scheme based on the
/// top level target sum encoding using Poseidon2
pub mod instantiations_poseidon_top_level;
/// Instantiations of the generalized XMSS signature scheme based on SHA
pub mod instantiations_sha;

#[cfg(test)]
mod tests {
    use crate::{
        inc_encoding::{basic_winternitz::WinternitzEncoding, target_sum::TargetSumEncoding},
        signature::test_templates::test_signature_scheme_correctness,
        symmetric::{
            message_hash::{
                MessageHash,
                poseidon::PoseidonMessageHashW1,
                sha::{ShaMessageHash, ShaMessageHash192x3},
            },
            prf::{sha::ShaPRF, shake_to_field::ShakePRFtoF},
            tweak_hash::{poseidon::PoseidonTweakW1L5, sha::ShaTweak192192},
        },
    };

    use super::*;

    #[test]
    pub fn test_winternitz() {
        // Note: do not use these parameters, they are just for testing
        type PRF = ShaPRF<24>;
        type TH = ShaTweak192192;
        type MH = ShaMessageHash192x3;
        const CHUNK_SIZE: usize = 4;
        const NUM_CHUNKS_CHECKSUM: usize = 3;
        type IE = WinternitzEncoding<MH, CHUNK_SIZE, NUM_CHUNKS_CHECKSUM>;
        const LOG_LIFETIME: usize = 9;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        Sig::internal_consistency_check();

        test_signature_scheme_correctness::<Sig>(289, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(2, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(19, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(0, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(11, 0, Sig::LIFETIME as usize);
    }

    #[test]
    pub fn test_winternitz_poseidon() {
        // Note: do not use these parameters, they are just for testing
        type PRF = ShakePRFtoF<7>;
        type TH = PoseidonTweakW1L5;
        type MH = PoseidonMessageHashW1;
        const CHUNK_SIZE: usize = 1;
        const _BASE: usize = 2;
        const NUM_CHUNKS_CHECKSUM: usize = 8;
        type IE = WinternitzEncoding<MH, CHUNK_SIZE, NUM_CHUNKS_CHECKSUM>;
        const LOG_LIFETIME: usize = 5;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        Sig::internal_consistency_check();

        test_signature_scheme_correctness::<Sig>(2, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(19, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(0, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(11, 0, Sig::LIFETIME as usize);

        test_signature_scheme_correctness::<Sig>(12, 10, (1 << 5) - 10);
        test_signature_scheme_correctness::<Sig>(19, 4, 20);
        test_signature_scheme_correctness::<Sig>(16, 16, 4);
        test_signature_scheme_correctness::<Sig>(11, 1, 29);
    }

    #[test]
    pub fn test_target_sum() {
        // Note: do not use these parameters, they are just for testing
        type PRF = ShaPRF<24>;
        type TH = ShaTweak192192;
        type MH = ShaMessageHash192x3;
        const BASE: usize = MH::BASE;
        const NUM_CHUNKS: usize = MH::DIMENSION;
        const MAX_CHUNK_VALUE: usize = BASE - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 8;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        Sig::internal_consistency_check();

        test_signature_scheme_correctness::<Sig>(13, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(9, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(21, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(0, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(31, 0, Sig::LIFETIME as usize);
    }

    #[test]
    pub fn test_target_sum_poseidon() {
        // Note: do not use these parameters, they are just for testing
        type PRF = ShakePRFtoF<7>;
        type TH = PoseidonTweakW1L5;
        type MH = PoseidonMessageHashW1;
        const BASE: usize = MH::BASE;
        const NUM_CHUNKS: usize = MH::DIMENSION;
        const MAX_CHUNK_VALUE: usize = BASE - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 5;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        Sig::internal_consistency_check();

        test_signature_scheme_correctness::<Sig>(2, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(19, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(0, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(11, 0, Sig::LIFETIME as usize);
    }

    #[test]
    pub fn test_large_base_sha() {
        // Note: do not use these parameters, they are just for testing
        type PRF = ShaPRF<24>;
        type TH = ShaTweak192192;

        // use chunk size 8
        type MH = ShaMessageHash<24, 8, 32, 8>;
        const TARGET_SUM: usize = 1 << 12;
        type IE = TargetSumEncoding<MH, TARGET_SUM>;
        const LOG_LIFETIME: usize = 9;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        Sig::internal_consistency_check();

        test_signature_scheme_correctness::<Sig>(0, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(11, 0, Sig::LIFETIME as usize);
    }

    #[test]
    pub fn test_large_dimension_sha() {
        // Note: do not use these parameters, they are just for testing
        type PRF = ShaPRF<24>;
        type TH = ShaTweak192192;

        // use 256 chunks
        type MH = ShaMessageHash<24, 8, 256, 1>;
        const TARGET_SUM: usize = 128;
        type IE = TargetSumEncoding<MH, TARGET_SUM>;
        const LOG_LIFETIME: usize = 9;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        Sig::internal_consistency_check();

        test_signature_scheme_correctness::<Sig>(2, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(19, 0, Sig::LIFETIME as usize);
    }
}
