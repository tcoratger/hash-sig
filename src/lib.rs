use p3_koala_bear::{
    KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_16, default_koalabear_poseidon2_24,
};

/// Message length in bytes, for messages that we want to sign.
pub const MESSAGE_LENGTH: usize = 32;

pub const TWEAK_SEPARATOR_FOR_MESSAGE_HASH: u8 = 0x02;
pub const TWEAK_SEPARATOR_FOR_TREE_HASH: u8 = 0x01;
pub const TWEAK_SEPARATOR_FOR_CHAIN_HASH: u8 = 0x00;

type F = KoalaBear;

/// The Poseidon2 of width 16 used in the codebase.
pub(crate) fn poseidon16() -> Poseidon2KoalaBear<16> {
    default_koalabear_poseidon2_16()
}

/// The Poseidon2 of width 24 used in the codebase.
pub(crate) fn poseidon24() -> Poseidon2KoalaBear<24> {
    default_koalabear_poseidon2_24()
}

pub mod hypercube;
pub mod inc_encoding;
pub mod signature;
pub mod symmetric;
