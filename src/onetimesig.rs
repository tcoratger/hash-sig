use rand::Rng;

/// Trait to model a one-time signature scheme
/// Note: we assume that the message space if given by a subset of
/// message digests, and so the scheme needs to specify a function
/// to determine if a message digest is "valid". This can then be
/// extended to any message using seeds.
pub trait OneTimeSignatureScheme {
    type PublicKey;
    type SecretKey;
    type Signature;
    type Digest;

    /// Generates a new key pair, returning the public and private keys.
    fn gen<R: Rng>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey);

    /// Checks if a message digest is valid.
    fn is_digest_valid(digest: &Self::Digest) -> bool;

    /// Signs a message (given by its digest) and returns the signature.
    fn sign(sk: &Self::SecretKey, digest: &Self::Digest) -> Self::Signature;

    /// Verifies a signature with respect to public key and message digest.
    fn verify(pk: &Self::PublicKey, digest: &Self::Digest, sig: &Self::Signature) -> bool;
}

pub mod fixed_sum_winternitz;
pub mod lamport;
pub mod permuted_winternitz;
pub mod winternitz;
