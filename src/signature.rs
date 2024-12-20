use rand::Rng;

/// Error enum for signatures
#[derive(Debug)]
pub enum SigningError {
    InvalidMessageLength,
    UnluckyFailure,
}

/// Trait to model a synchronized signature scheme.
/// We sign messages with respect to epochs.
/// We assume each we sign for each epoch only once.
pub trait SignatureScheme {
    type PublicKey;
    type SecretKey;
    type Signature;

    /// Generates a new key pair, returning the public and private keys.
    fn gen<R: Rng>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey);

    /// Signs a message and returns the signature.
    /// The signature is with respect to a given epoch.
    fn sign<R: Rng>(
        rng: &mut R,
        sk: &Self::SecretKey,
        epoch: u64,
        message: &[u8; 64],
    ) -> Result<Self::Signature, SigningError>;

    /// Verifies a signature with respect to public key, epoch, and message digest.
    fn verify(pk: &Self::PublicKey, epoch: u64, message: &[u8; 64], sig: &Self::Signature) -> bool;
}

mod generalized_xmss;
