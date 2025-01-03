use rand::Rng;

/// Trait to model a pseudorandom function
pub trait Pseudorandom {
    type Key;
    type Output;

    /// Sample a random domain element
    fn gen<R: Rng>(rng: &mut R) -> Self::Key;

    /// Apply the one-way function to an epoch and an index
    fn apply(key: &Self::Key, epoch: u32, index: u64) -> Self::Output;
}

pub mod hashprf;
