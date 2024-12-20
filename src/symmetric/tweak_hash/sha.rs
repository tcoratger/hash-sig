use sha2::{Digest, Sha256};

use super::TweakableHash;

/// Enum to implement tweaks.
pub enum Sha256Tweak {
    TreeTweak {
        level: u64,
        pos_in_level: u64,
    },
    ChainTweak {
        epoch: u64,
        chain_index: u64,
        pos_in_chain: u64,
    },
}

impl Sha256Tweak {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Sha256Tweak::TreeTweak {
                level,
                pos_in_level,
            } => {
                let mut bytes = Vec::new();
                // this is a tree tweak, so we start with a 0x00 byte
                bytes.push(0x00);
                // then we extend with the actual data
                bytes.extend(&level.to_be_bytes());
                bytes.extend(&pos_in_level.to_be_bytes());
                // and finally a 64 0-bits to ensure the same length
                bytes.extend_from_slice(&[0; 8]);
                bytes
            }
            Sha256Tweak::ChainTweak {
                epoch,
                chain_index,
                pos_in_chain,
            } => {
                let mut bytes = Vec::new();
                // this is a chain tweak, so we start with a 0x01 byte
                bytes.push(0x01);
                // then we extend with the actual data
                bytes.extend(&epoch.to_be_bytes());
                bytes.extend(&chain_index.to_be_bytes());
                bytes.extend(&pos_in_chain.to_be_bytes());
                bytes
            }
        }
    }
}

/// A tweakable hash function implemented using
/// SHA-256, given a parameter length and the hash output length.
/// Both lengths must be given in Bytes.
/// Both lengths must be less than 255 bits.
pub struct Sha256TweakHash<const PARAMETER_LEN: usize, const HASH_LEN: usize>;

impl<const PARAMETER_LEN: usize, const HASH_LEN: usize> TweakableHash
    for Sha256TweakHash<PARAMETER_LEN, HASH_LEN>
{
    type Parameter = [u8; PARAMETER_LEN];

    type Tweak = Sha256Tweak;

    type Domain = [u8; HASH_LEN];

    fn rand_parameter<R: rand::Rng>(rng: &mut R) -> Self::Parameter {
        let mut par = [0u8; PARAMETER_LEN];
        rng.fill_bytes(&mut par);
        par
    }

    fn rand_domain<R: rand::Rng>(rng: &mut R) -> Self::Domain {
        let mut dom = [0u8; HASH_LEN];
        rng.fill_bytes(&mut dom);
        dom
    }

    fn tree_tweak(level: u64, pos_in_level: u64) -> Self::Tweak {
        Sha256Tweak::TreeTweak {
            level,
            pos_in_level,
        }
    }

    fn chain_tweak(epoch: u64, chain_index: u64, pos_in_chain: u64) -> Self::Tweak {
        Sha256Tweak::ChainTweak {
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
        assert!(
            PARAMETER_LEN <= 255,
            "SHA256-Tweak Hash: Parameter Length must be at most 255 bit"
        );
        assert!(
            HASH_LEN <= 255,
            "SHA256-Tweak Hash: Parameter Length must be at most 255 bit"
        );

        let mut hasher = Sha256::new();

        // first add the lengths of parameters and tweaks
        // we assume they only use 8 bits = 1 Byte
        let par_len: u8 = PARAMETER_LEN.to_le_bytes()[0];
        let tweak_len: u8 = (8 + 64 + 64 + 64) / 8;
        hasher.update(&[par_len]);
        hasher.update(&[tweak_len]);
        hasher.update(&[0x00]);

        // now add the parameter and tweak
        hasher.update(parameter);
        hasher.update(tweak.to_bytes());

        // now add the actual message to be hashed
        for m in message {
            hasher.update(m);
        }

        // finalize the hash, and take as many bytes as we need
        let result = hasher.finalize();
        result[0..=HASH_LEN].try_into().unwrap()
    }
}



// Example instantiations
pub type Sha256Tweak128128 = Sha256TweakHash<128, 128>;
pub type Sha256Tweak128192 = Sha256TweakHash<128, 192>;
pub type Sha256Tweak192192 = Sha256TweakHash<192, 192>;