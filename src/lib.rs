use p3_baby_bear::{
    BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16, default_babybear_poseidon2_24,
};

/// Message length in bytes, for messages that we want to sign.
pub const MESSAGE_LENGTH: usize = 32;

pub const TWEAK_SEPARATOR_FOR_MESSAGE_HASH: u8 = 0x02;
pub const TWEAK_SEPARATOR_FOR_TREE_HASH: u8 = 0x01;
pub const TWEAK_SEPARATOR_FOR_CHAIN_HASH: u8 = 0x00;

type F = BabyBear;

pub(crate) mod hypercube;
pub(crate) mod inc_encoding;
pub mod signature;
pub(crate) mod symmetric;

/// Poseidon2 permutation (width 24)
pub(crate) fn poseidon2_24() -> Poseidon2BabyBear<24> {
    default_babybear_poseidon2_24()
}

/// Poseidon2 permutation (width 16)
pub(crate) fn poseidon2_16() -> Poseidon2BabyBear<16> {
    default_babybear_poseidon2_16()
}
