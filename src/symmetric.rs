use rand::Rng;

/// Trait to model a one-way function
pub trait OneWay {
    type Domain: Copy + Default + PartialEq + Sized;

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

    /// Apply the one-way function
    fn apply(key: &Self::Key, input: u64) -> Self::Output;
}

pub mod hashprf;
pub mod sha;
pub mod hashtree;
