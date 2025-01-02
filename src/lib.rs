/// Message length in bytes, for messages
/// that we want to sign.
pub const MESSAGE_LENGTH: usize = 64;

pub mod inc_encoding;
pub mod signature;
pub mod symmetric;
