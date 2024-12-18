use std::fmt::Debug;

use rand::Rng;

/// Trait to model a one-way function
pub trait OneWay {
    type Domain: Copy + Default + PartialEq + Sized + Debug;

    /// Apply the one-way function
    fn apply(input: &[Self::Domain]) -> Self::Domain;

    /// Sample a random domain element
    fn sample<R: Rng>(rng: &mut R) -> Self::Domain;
}

/// Trait to model a pseudorandom function
pub trait Pseudorandom {
    type Key;
    type Output;

    /// Sample a random domain element
    fn gen<R: Rng>(rng: &mut R) -> Self::Key;

    /// Apply the one-way function to an epoch and an index
    fn apply(key: &Self::Key, epoch: u64, index: u64) -> Self::Output;
}

/// Trait to model a (deterministic) vector commitment, such as a Merkle Tree
pub trait VectorCommitment {
    type Domain;
    type Commitment;
    type Opening;

    /// Commit to a vector
    fn commit(vector: &[Self::Domain]) -> Self::Commitment;

    /// Open the commitment at a position
    fn open(vector: &[Self::Domain], position: u64) -> Self::Opening;

    /// Verify an opening with respect to a commitment
    fn verify(com: &Self::Commitment, position: u64, opening: &Self::Opening) -> bool;
}

pub mod hashprf;
pub mod hashtree;
pub mod sha;

pub mod tweak_hash_tree;
