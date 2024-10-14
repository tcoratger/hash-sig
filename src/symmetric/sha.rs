use super::OneWay;
use sha2::{Digest, Sha256};

// Implement OneWay trait for SHA-256
pub struct Sha256Hash;

impl OneWay for Sha256Hash {
    type Domain = [u8; 32];

    fn apply(input: &[Self::Domain]) -> Self::Domain {
        let mut hasher = Sha256::new();
        for element in input {
            hasher.update(element);
        }
        let result = hasher.finalize();
        result.into()
    }

    fn sample<R: rand::Rng>(rng: &mut R) -> Self::Domain {
        let mut element = [0u8; 32];
        rng.fill(&mut element);
        element
    }
}
