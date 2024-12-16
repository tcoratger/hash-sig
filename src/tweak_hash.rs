use rand::Rng;

/// Trait to model a tweakable hash function.
/// Such a function takes a public parameter, a tweak, and a
/// message to be hashed. The tweak should be understood as an
/// address for domain separation.
///
/// In our setting, we require the support of hashing lists of
/// hashes. Therefore, we just define a type `Domain` and the
/// hash function maps from [Domain] to Domain.
///
/// We also require that the tweak hash already specifies how
/// to obtain distinct tweaks for applications in chains and
/// applications in Merkle trees.
pub trait TweakableHash {
    type Parameter;
    type Tweak;
    type Domain: Copy + Default + PartialEq + Sized;

    /// Generates a random public parameter.
    fn rand_parameter<R: Rng>(rng: &mut R) -> Self::Parameter;

    /// Generates a random domain element.
    fn rand_domain<R: Rng>(rng: &mut R) -> Self::Domain;

    /// Returns a tweak to be used in the Merkle tree.
    /// Note: this is assumed to be distinct from the outputs of chain_tweak
    fn tree_tweak(level: u64, pos_in_level: u64) -> Self::Tweak;

    /// Returns a tweak to be used in chains.
    /// Note: this is assumed to be distinct from the outputs of tree_tweak
    fn chain_tweak(epoch: u64, chain: u64, pos_in_chain: u64) -> Self::Tweak;

    /// Applies the tweakable hash to parameter, tweak, and message.
    fn apply(
        parameter: &Self::Parameter,
        tweak: &Self::Tweak,
        message: &[Self::Domain],
    ) -> Self::Domain;
}
