use rand::Rng;

/// Error during encoding
pub type EncodingError = ();

/// Trait to model incomparable encoding schemes.
/// These schemes allow to encode a message into a codeword.
/// And no two distinct codewords are "comparable", i.e.,
/// for no two codewords x = (x_1,..,x_k) and x' = (x'_1,..,x'_k)
/// we have x_i > x_i' for all i = 1,...,k.
pub trait IncomparableEncoding {
    type Parameter;
    type Message;
    type Randomness;
    type Range;

    /// Checks if a given element is in the code.
    fn is_in_code(x: &Self::Range) -> bool;

    /// Samples a randomness to be used for the encoding.
    fn rand<R: Rng>(rng: &mut R) -> Self::Randomness;

    /// Apply the incomparable encoding to a message.
    /// It could happen that this fails.
    fn encode(
        parameter: &Self::Parameter,
        message: &Self::Message,
        randomness: &Self::Randomness,
        epoch: u64,
    ) -> Result<Self::Range, EncodingError>;
}
