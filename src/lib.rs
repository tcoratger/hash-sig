pub mod onetimesig;
pub mod symmetric;

// //-------------------------------------------------------------------------------------

// /// Trait to model an indexed signature scheme.
// /// In such a scheme, we sign with respect to slots/indices.
// /// We assume each we sign for each slot/index only once.
// pub trait IndexedSignatureScheme {
//     type PublicKey;
//     type SecretKey;
//     type Signature;

//     /// Generates a new key pair, returning the public and private keys.
//     fn gen() -> (Self::PublicKey, Self::SecretKey);

//     /// Signs a message (given by its digest) and returns the signature.
//     fn sign(sk: &Self::SecretKey, index: u32, digest: &[u8; 32]) -> Self::Signature;

//     /// Verifies a signature with respect to public key and message digest.
//     fn verify(pk: &Self::PublicKey, index: u32, digest: &[u8; 32], sig: &Self::Signature) -> bool;
// }
