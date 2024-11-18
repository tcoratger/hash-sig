use rand::Rng;

/// Trait to model a one-time signature scheme
pub trait OneTimeSignatureScheme {
    type PublicKey;
    type SecretKey;
    type Signature;
    type Digest;

    /// Generates a new key pair, returning the public and private keys.
    fn gen<R: Rng>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey);

    /// Generates a random digest (e.g., used for test purposes)
    fn rand_digest<R: Rng>(rng: &mut R) -> Self::Digest;

    /// Signs a message (given by its digest) and returns the signature.
    fn sign(sk: &Self::SecretKey, digest: &Self::Digest) -> Self::Signature;

    /// Verifies a signature with respect to public key and message digest.
    fn verify(pk: &Self::PublicKey, digest: &Self::Digest, sig: &Self::Signature) -> bool;
}

pub mod fixed_sum_winternitz;
pub mod lamport;
pub mod permuted_winternitz;
pub mod winternitz;

/// Module that contains templates for tests that can be used
/// by concrete instantiations of OneTimeSignatureScheme
mod test_templates {
    use super::*;
    use rand::thread_rng;

    /// Template for tests: honest key gen, sign, and verify for
    /// a random digest. Verification should accept.
    pub fn _honest_signing_verification_template<OTS : OneTimeSignatureScheme>() {
        let mut rng = thread_rng();
        let (pk, sk) = OTS::gen(&mut rng);

        let digest = OTS::rand_digest(&mut rng);

        let signature = OTS::sign(&sk, &digest);

        let is_valid = OTS::verify(&pk, &digest, &signature);
        assert!(
            is_valid,
            "The signature should be valid with correct keys and message."
        );
    }

    /// Template for tests: honest key gen, and sign for
    /// a random digest, but then verify for other digest.
    /// Verification should reject.
    pub fn _wrong_digest_verification_template<OTS : OneTimeSignatureScheme>() where <OTS as OneTimeSignatureScheme>::Digest: PartialEq {
        let mut rng = thread_rng();
        let (pk, sk) = OTS::gen(&mut rng);

        let digest = OTS::rand_digest(&mut rng);
        let other_digest = OTS::rand_digest(&mut rng);

        let signature = OTS::sign(&sk, &digest);

        let is_valid = OTS::verify(&pk, &other_digest, &signature);
        let are_the_same = digest == other_digest;
        assert!(
            !is_valid || are_the_same,
            "The signature should not be valid for a different digest."
        );
    }
}
