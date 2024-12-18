/// Lifetime of a key, i.e., the key can be used
/// for LIFETIME many epochs.
const LIFETIME: usize = 1 << 10;

/// Message length in bytes, for messages
/// that we want to sign
const MESSAGE_LENGTH: usize = 32;

pub mod symmetric;
pub mod inc_encoding;
pub mod signature;