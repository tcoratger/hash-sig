use p3_baby_bear::default_babybear_poseidon2_16;
use p3_baby_bear::default_babybear_poseidon2_24;
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_field::PrimeField64;
use p3_symmetric::CryptographicHasher;
use p3_symmetric::PaddingFreeSponge;
use p3_symmetric::Permutation;

use crate::TWEAK_SEPARATOR_FOR_CHAIN_HASH;
use crate::TWEAK_SEPARATOR_FOR_TREE_HASH;

use super::TweakableHash;

type F = BabyBear;

/// Modulus of the field as u128
///
/// Note: It's fine to take only the first limb as we are using prime fields with <= 64 bits
const MODULUS_128: u128 = F::ORDER_U64 as u128;

const DOMAIN_PARAMETERS_LENGTH: usize = 4;

/// Enum to implement tweaks.
pub enum PoseidonTweak {
    TreeTweak {
        level: u8,
        pos_in_level: u32,
    },
    ChainTweak {
        epoch: u32,
        chain_index: u8,
        pos_in_chain: u8,
    },
}

impl PoseidonTweak {
    fn to_field_elements<const TWEAK_LEN: usize>(&self) -> [F; TWEAK_LEN] {
        // We first represent the entire tweak as one big integer
        let mut acc = match self {
            Self::TreeTweak {
                level,
                pos_in_level,
            } => {
                ((*level as u128) << 40)
                    | ((*pos_in_level as u128) << 8)
                    | (TWEAK_SEPARATOR_FOR_TREE_HASH as u128)
            }
            Self::ChainTweak {
                epoch,
                chain_index,
                pos_in_chain,
            } => {
                ((*epoch as u128) << 24)
                    | ((*chain_index as u128) << 16)
                    | ((*pos_in_chain as u128) << 8)
                    | (TWEAK_SEPARATOR_FOR_CHAIN_HASH as u128)
            }
        };

        // Get the modulus
        let p = MODULUS_128;

        // Now we interpret this integer in base-p to get field elements
        std::array::from_fn(|_| {
            let digit = acc % p;
            acc /= p;
            F::from_u128(digit)
        })
    }
}

/// A tweakable hash function implemented using Poseidon2
///
/// Note: HASH_LEN, TWEAK_LEN, CAPACITY, and PARAMETER_LEN must
/// be given in the unit "number of field elements".
pub struct PoseidonTweakHash<
    const PARAMETER_LEN: usize,
    const HASH_LEN: usize,
    const TWEAK_LEN: usize,
    const CAPACITY: usize,
    const NUM_CHUNKS: usize,
>;

impl<
        const PARAMETER_LEN: usize,
        const HASH_LEN: usize,
        const TWEAK_LEN: usize,
        const CAPACITY: usize,
        const NUM_CHUNKS: usize,
    > TweakableHash
    for PoseidonTweakHash<PARAMETER_LEN, HASH_LEN, TWEAK_LEN, CAPACITY, NUM_CHUNKS>
{
    type Parameter = [F; PARAMETER_LEN];

    type Tweak = PoseidonTweak;

    type Domain = [F; HASH_LEN];

    fn rand_parameter<R: rand::Rng>(rng: &mut R) -> Self::Parameter {
        rng.random()
    }

    fn rand_domain<R: rand::Rng>(rng: &mut R) -> Self::Domain {
        rng.random()
    }

    fn tree_tweak(level: u8, pos_in_level: u32) -> Self::Tweak {
        PoseidonTweak::TreeTweak {
            level,
            pos_in_level,
        }
    }

    fn chain_tweak(epoch: u32, chain_index: u8, pos_in_chain: u8) -> Self::Tweak {
        PoseidonTweak::ChainTweak {
            epoch,
            chain_index,
            pos_in_chain,
        }
    }

    fn apply(
        parameter: &Self::Parameter,
        tweak: &Self::Tweak,
        message: &[Self::Domain],
    ) -> Self::Domain {
        // we are in one of three cases:
        // (1) hashing within chains. We use compression mode.
        // (2) hashing two siblings in the tree. We use compression mode.
        // (3) hashing a long vector of chain ends. We use sponge mode.

        let tweak_fe = tweak.to_field_elements::<TWEAK_LEN>();

        match message {
            // Case 1: Hashing one block (chaining), using width-16 compression.
            [single] => {
                let perm = default_babybear_poseidon2_16();

                let mut combined_input = [F::ZERO; 16];
                let mut offset = 0;
                combined_input[offset..offset + PARAMETER_LEN].copy_from_slice(parameter);
                offset += PARAMETER_LEN;
                combined_input[offset..offset + TWEAK_LEN].copy_from_slice(&tweak_fe);
                offset += TWEAK_LEN;
                combined_input[offset..offset + HASH_LEN].copy_from_slice(single);

                let mut state = combined_input;
                perm.permute_mut(&mut state);
                for i in 0..16 {
                    state[i] += combined_input[i];
                }

                state[0..HASH_LEN]
                    .try_into()
                    .expect("Slice with incorrect length")
            }

            // Case 2: Hashing two blocks (tree node), using width-24 compression.
            [left, right] => {
                let perm = default_babybear_poseidon2_24();

                let mut combined_input = [F::ZERO; 24];
                let mut offset = 0;
                combined_input[offset..offset + PARAMETER_LEN].copy_from_slice(parameter);
                offset += PARAMETER_LEN;
                combined_input[offset..offset + TWEAK_LEN].copy_from_slice(&tweak_fe);
                offset += TWEAK_LEN;
                combined_input[offset..offset + HASH_LEN].copy_from_slice(left);
                offset += HASH_LEN;
                combined_input[offset..offset + HASH_LEN].copy_from_slice(right);

                let mut state = combined_input;
                perm.permute_mut(&mut state);
                for i in 0..24 {
                    state[i] += combined_input[i];
                }

                state[..HASH_LEN]
                    .try_into()
                    .expect("Slice with incorrect length")
            }

            // Case 3: Hashing many blocks, using the idiomatic sponge construction.
            _ => {
                // Instantiate the correct sponge hasher struct: `PaddingFreeSponge`.
                // We use a RATE of 16, a standard choice for a width-24 sponge.
                // The output size `OUT` is the `HASH_LEN` of our TweakableHash.
                const RATE: usize = 16;

                // Get the default Poseidon2 permutation with a width of 24.
                let permutation = default_babybear_poseidon2_24();

                let hasher = PaddingFreeSponge::<_, 24, RATE, HASH_LEN>::new(permutation);

                // Prepare the domain separation prefix.
                let lengths: [F; DOMAIN_PARAMETERS_LENGTH] = [
                    F::from_u32(PARAMETER_LEN as u32),
                    F::from_u32(TWEAK_LEN as u32),
                    F::from_u32(NUM_CHUNKS as u32),
                    F::from_u32(HASH_LEN as u32),
                ];

                // Create an iterator that chains all data to be hashed.
                let elements_to_hash = lengths
                    .iter()
                    .chain(parameter.iter())
                    .chain(tweak_fe.iter())
                    .chain(message.iter().flatten())
                    .copied();

                // Call the hasher.
                hasher.hash_iter(elements_to_hash)
            }
        }
    }

    #[cfg(test)]
    fn internal_consistency_check() {
        use num_bigint::BigUint;

        assert!(
            BigUint::from(F::ORDER_U64) < BigUint::from(u64::MAX),
            "The prime field used is too large"
        );
        assert!(
            CAPACITY < 24,
            "Poseidon Tweak Chain Hash: Capacity must be less than 24"
        );
        assert!(
            PARAMETER_LEN + TWEAK_LEN + HASH_LEN <= 16,
            "Poseidon Tweak Chain Hash: Input lengths too large for Poseidon instance"
        );
        assert!(
            PARAMETER_LEN + TWEAK_LEN + 2 * HASH_LEN <= 24,
            "Poseidon Tweak Tree Hash: Input lengths too large for Poseidon instance"
        );

        let bits_per_fe = f64::floor(f64::log2(
            BigUint::from(F::ORDER_U64).to_string().parse().unwrap(),
        ));
        let state_bits = bits_per_fe * f64::from(24_u32);
        assert!(
            state_bits >= f64::from((DOMAIN_PARAMETERS_LENGTH * 32) as u32),
            "Poseidon Tweak Leaf Hash: not enough field elements to hash the domain separator"
        );

        let bits_for_tree_tweak = f64::from(32 + 8_u32);
        let bits_for_chain_tweak = f64::from(32 + 8 + 8 + 8_u32);
        let tweak_fe_bits = bits_per_fe * f64::from(TWEAK_LEN as u32);
        assert!(
            tweak_fe_bits >= bits_for_tree_tweak,
            "Poseidon Tweak Hash: not enough field elements to encode the tree tweak"
        );
        assert!(
            tweak_fe_bits >= bits_for_chain_tweak,
            "Poseidon Tweak Hash: not enough field elements to encode the chain tweak"
        );
    }
}

// Example instantiations
pub type PoseidonTweak44 = PoseidonTweakHash<4, 4, 3, 9, 128>;
pub type PoseidonTweak37 = PoseidonTweakHash<3, 7, 3, 9, 128>;
pub type PoseidonTweakW1L18 = PoseidonTweakHash<5, 7, 2, 9, 163>;
pub type PoseidonTweakW1L5 = PoseidonTweakHash<5, 7, 2, 9, 163>;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use num_bigint::BigUint;
    use rand::Rng;

    use super::*;

    #[test]
    fn test_apply_44() {
        let mut rng = rand::rng();

        // make sure parameters make sense
        PoseidonTweak44::internal_consistency_check();

        // test that nothing is panicking
        let parameter = PoseidonTweak44::rand_parameter(&mut rng);
        let message_one = PoseidonTweak44::rand_domain(&mut rng);
        let message_two = PoseidonTweak44::rand_domain(&mut rng);
        let tweak_tree = PoseidonTweak44::tree_tweak(0, 3);
        PoseidonTweak44::apply(&parameter, &tweak_tree, &[message_one, message_two]);

        // test that nothing is panicking
        let parameter = PoseidonTweak44::rand_parameter(&mut rng);
        let message_one = PoseidonTweak44::rand_domain(&mut rng);
        let tweak_chain = PoseidonTweak44::chain_tweak(2, 3, 4);
        PoseidonTweak44::apply(&parameter, &tweak_chain, &[message_one]);

        // test that nothing is panicking
        let parameter = PoseidonTweak44::rand_parameter(&mut rng);
        let chains = [PoseidonTweak44::rand_domain(&mut rng); 128];
        let tweak_tree = PoseidonTweak44::tree_tweak(0, 3);
        PoseidonTweak44::apply(&parameter, &tweak_tree, &chains);
    }

    #[test]
    fn test_apply_37() {
        let mut rng = rand::rng();

        // make sure parameters make sense
        PoseidonTweak37::internal_consistency_check();

        // test that nothing is panicking
        let parameter = PoseidonTweak37::rand_parameter(&mut rng);
        let message_one = PoseidonTweak37::rand_domain(&mut rng);
        let message_two = PoseidonTweak37::rand_domain(&mut rng);
        let tweak_tree = PoseidonTweak37::tree_tweak(0, 3);
        PoseidonTweak37::apply(&parameter, &tweak_tree, &[message_one, message_two]);

        // test that nothing is panicking
        let parameter = PoseidonTweak37::rand_parameter(&mut rng);
        let message_one = PoseidonTweak37::rand_domain(&mut rng);
        let tweak_chain = PoseidonTweak37::chain_tweak(2, 3, 4);
        PoseidonTweak37::apply(&parameter, &tweak_chain, &[message_one]);
    }

    #[test]
    fn test_rand_parameter_not_all_same() {
        // Setup a umber of trials
        const K: usize = 10;
        let mut rng = rand::rng();
        let mut all_same_count = 0;

        for _ in 0..K {
            let parameter = PoseidonTweak44::rand_parameter(&mut rng);

            // Check if all elements in `parameter` are identical
            let first = parameter[0];
            if parameter.iter().all(|&x| x == first) {
                all_same_count += 1;
            }
        }

        // If all K trials resulted in identical values, fail the test
        assert!(
            all_same_count < K,
            "rand_parameter generated identical elements in all {K} trials"
        );
    }

    #[test]
    fn test_rand_domain_not_all_same() {
        // Setup a umber of trials
        const K: usize = 10;
        let mut rng = rand::rng();
        let mut all_same_count = 0;

        for _ in 0..K {
            let domain = PoseidonTweak44::rand_domain(&mut rng);

            // Check if all elements in `domain` are identical
            let first = domain[0];
            if domain.iter().all(|&x| x == first) {
                all_same_count += 1;
            }
        }

        // If all K trials resulted in identical values, fail the test
        assert!(
            all_same_count < K,
            "rand_domain generated identical elements in all {} trials",
            K
        );
    }

    #[test]
    fn test_tree_tweak_field_elements() {
        // Tweak
        let level = 1u8;
        let pos_in_level = 2u32;
        let sep = TWEAK_SEPARATOR_FOR_TREE_HASH as u64;

        // Compute tweak_bigint
        let tweak_bigint: BigUint =
            (BigUint::from(level) << 40) + (BigUint::from(pos_in_level) << 8) + sep;

        // Use the field modulus
        let p = BigUint::from(F::ORDER_U64);

        // Extract field elements in base-p
        let expected = [
            F::from_u128((&tweak_bigint % &p).try_into().unwrap()),
            F::from_u128(((&tweak_bigint / &p) % &p).try_into().unwrap()),
        ];

        // Check actual output
        let tweak = PoseidonTweak::TreeTweak {
            level,
            pos_in_level,
        };
        let computed = tweak.to_field_elements::<2>();
        assert_eq!(computed, expected);
    }

    #[test]
    fn test_chain_tweak_field_elements() {
        // Tweak
        let epoch = 1u32;
        let chain_index = 2u8;
        let pos_in_chain = 3u8;
        let sep = TWEAK_SEPARATOR_FOR_CHAIN_HASH as u64;

        // Compute tweak_bigint = (epoch << 24) + (chain_index << 16) + (pos_in_chain << 8) + sep
        let tweak_bigint: BigUint = (BigUint::from(epoch) << 24)
            + (BigUint::from(chain_index) << 16)
            + (BigUint::from(pos_in_chain) << 8)
            + sep;

        // Use the field modulus
        let p = BigUint::from(F::ORDER_U64);

        // Extract field elements in base-p
        let expected = [
            F::from_u128((&tweak_bigint % &p).try_into().unwrap()),
            F::from_u128(((&tweak_bigint / &p) % &p).try_into().unwrap()),
        ];

        // Check actual output
        let tweak = PoseidonTweak::ChainTweak {
            epoch,
            chain_index,
            pos_in_chain,
        };
        let computed = tweak.to_field_elements::<2>();
        assert_eq!(computed, expected);
    }

    #[test]
    fn test_tree_tweak_field_elements_max_values() {
        let level = u8::MAX;
        let pos_in_level = u32::MAX;
        let sep = TWEAK_SEPARATOR_FOR_TREE_HASH as u64;

        let tweak_bigint: BigUint =
            (BigUint::from(level) << 40) + (BigUint::from(pos_in_level) << 8) + sep;

        let p = BigUint::from(F::ORDER_U64);
        let expected = [
            F::from_u128((&tweak_bigint % &p).try_into().unwrap()),
            F::from_u128(((&tweak_bigint / &p) % &p).try_into().unwrap()),
        ];

        let tweak = PoseidonTweak::TreeTweak {
            level,
            pos_in_level,
        };
        let computed = tweak.to_field_elements::<2>();
        assert_eq!(computed, expected);
    }

    #[test]
    fn test_chain_tweak_field_elements_max_values() {
        let epoch = u32::MAX;
        let chain_index = u8::MAX;
        let pos_in_chain = u8::MAX;
        let sep = TWEAK_SEPARATOR_FOR_CHAIN_HASH as u64;

        let tweak_bigint: BigUint = (BigUint::from(epoch) << 24)
            + (BigUint::from(chain_index) << 16)
            + (BigUint::from(pos_in_chain) << 8)
            + sep;

        let p = BigUint::from(F::ORDER_U64);
        let expected = [
            F::from_u128((&tweak_bigint % &p).try_into().unwrap()),
            F::from_u128(((&tweak_bigint / &p) % &p).try_into().unwrap()),
        ];

        let tweak = PoseidonTweak::ChainTweak {
            epoch,
            chain_index,
            pos_in_chain,
        };
        let computed = tweak.to_field_elements::<2>();
        assert_eq!(computed, expected);
    }

    #[test]
    fn test_tree_tweak_injective() {
        let mut rng = rand::rng();

        // basic test to check that tree tweak maps from
        // parameters to field elements array injectively

        // random inputs
        let mut map = HashMap::new();
        for _ in 0..100_000 {
            let level = rng.random();
            let pos_in_level = rng.random();
            let tweak_encoding = PoseidonTweak::TreeTweak {
                level,
                pos_in_level,
            }
            .to_field_elements::<2>();

            if let Some((prev_level, prev_pos_in_level)) =
                map.insert(tweak_encoding, (level, pos_in_level))
            {
                assert_eq!(
                    (prev_level, prev_pos_in_level),
                    (level, pos_in_level),
                    "Collision detected for ({},{}) and ({},{}) with output {:?}",
                    prev_level,
                    prev_pos_in_level,
                    level,
                    pos_in_level,
                    tweak_encoding
                );
            }
        }

        // inputs with common level
        let mut map = HashMap::new();
        let level = rng.random();
        for _ in 0..10_000 {
            let pos_in_level = rng.random();
            let tweak_encoding = PoseidonTweak::TreeTweak {
                level,
                pos_in_level,
            }
            .to_field_elements::<2>();

            if let Some(prev_pos_in_level) = map.insert(tweak_encoding, pos_in_level) {
                assert_eq!(
                    prev_pos_in_level, pos_in_level,
                    "Collision detected for ({},{}) and ({},{}) with output {:?}",
                    level, prev_pos_in_level, level, pos_in_level, tweak_encoding
                );
            }
        }

        // inputs with common pos_in_level
        let mut map = HashMap::new();
        let pos_in_level = rng.random();
        for _ in 0..10_000 {
            let level = rng.random();
            let tweak_encoding = PoseidonTweak::TreeTweak {
                level,
                pos_in_level,
            }
            .to_field_elements::<2>();

            if let Some(prev_level) = map.insert(tweak_encoding, level) {
                assert_eq!(
                    prev_level, level,
                    "Collision detected for ({},{}) and ({},{}) with output {:?}",
                    prev_level, pos_in_level, level, pos_in_level, tweak_encoding
                );
            }
        }
    }

    #[test]
    fn test_chain_tweak_injective() {
        let mut rng = rand::rng();

        // basic test to check that chain tweak maps from
        // parameters to field element array injectively

        // random inputs
        let mut map = HashMap::new();
        for _ in 0..100_000 {
            let epoch = rng.random();
            let chain_index = rng.random();
            let pos_in_chain = rng.random();

            let input = (epoch, chain_index, pos_in_chain);

            let tweak_encoding = PoseidonTweak::ChainTweak {
                epoch,
                chain_index,
                pos_in_chain,
            }
            .to_field_elements::<2>();

            if let Some(prev_input) = map.insert(tweak_encoding, input) {
                assert_eq!(
                    prev_input, input,
                    "Collision detected for {prev_input:?} and {input:?} with output {tweak_encoding:?}"
                );
            }
        }

        // inputs with fixed epoch
        let mut map = HashMap::new();
        let epoch = rng.random();
        for _ in 0..10_000 {
            let chain_index = rng.random();
            let pos_in_chain = rng.random();

            let input = (chain_index, pos_in_chain);

            let tweak_encoding = PoseidonTweak::ChainTweak {
                epoch,
                chain_index,
                pos_in_chain,
            }
            .to_field_elements::<2>();

            if let Some(prev_input) = map.insert(tweak_encoding, input) {
                assert_eq!(
                    prev_input, input,
                    "Collision detected for {prev_input:?} and {input:?} with output {tweak_encoding:?}"
                );
            }
        }

        // inputs with fixed chain_index
        let mut map = HashMap::new();
        let chain_index = rng.random();
        for _ in 0..10_000 {
            let epoch = rng.random();
            let pos_in_chain = rng.random();

            let input = (epoch, pos_in_chain);

            let tweak_encoding = PoseidonTweak::ChainTweak {
                epoch,
                chain_index,
                pos_in_chain,
            }
            .to_field_elements::<2>();

            if let Some(prev_input) = map.insert(tweak_encoding, input) {
                assert_eq!(
                    prev_input, input,
                    "Collision detected for {prev_input:?} and {input:?} with output {tweak_encoding:?}"
                );
            }
        }

        // inputs with fixed pos_in_chain
        let mut map = HashMap::new();
        let pos_in_chain = rng.random();
        for _ in 0..10_000 {
            let epoch = rng.random();
            let chain_index = rng.random();

            let input = (epoch, chain_index);

            let tweak_encoding = PoseidonTweak::ChainTweak {
                epoch,
                chain_index,
                pos_in_chain,
            }
            .to_field_elements::<2>();

            if let Some(prev_input) = map.insert(tweak_encoding, input) {
                assert_eq!(
                    prev_input, input,
                    "Collision detected for {prev_input:?} and {input:?} with output {tweak_encoding:?}"
                );
            }
        }
    }
}
