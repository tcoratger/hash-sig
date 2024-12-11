use rand::Rng;


/// Trait to model a tweakable hash function.
/// Such a function takes a public parameter, a tweak, and a
/// message to be hashed. The tweak should be understood as an
/// address for domain separation.
///
/// We also require that the tweak hash already specifies how
/// to obtain distinct tweaks for applications in chains and
/// applications in Merkle trees.
pub trait TweakableHash {
    type Parameter;
    type Tweak;
    type Message;
    type Hash;

    /// Generates a random public parameter.
    fn rand_parameter<R: Rng>(rng: &mut R) -> Self::Parameter;

    /// Returns a tweak to be used in the Merkle tree.
    /// Note: this is assumed to be distinct from the outputs of chain_tweak
    fn tree_tweak(level : u64, pos_in_level : u64) -> Self::Tweak;

    /// Returns a tweak to be used in chains.
    /// Note: this is assumed to be distinct from the outputs of tree_tweak
    fn chain_tweak(epoch : u64, chain : u64, pos_in_chain : u64) -> Self::Tweak;

    /// Applies the tweakable hash to parameter, tweak, and message.
    fn apply(parameter : &Self::Parameter, tweak : &Self::Tweak, message : &Self::Message) -> Self::Hash;
}