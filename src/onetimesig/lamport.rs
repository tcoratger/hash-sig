use super::OneTimeSignatureScheme;
use crate::symmetric::{hashprf::Sha256PRF, sha::Sha256Hash};
use crate::symmetric::{OneWay, Pseudorandom};
use rand::Rng;

const MSG_LENGTH: usize = 32; // 32 bytes = 256 bit

pub struct Lamport<H: OneWay, PRF: Pseudorandom> {
    _marker_h: std::marker::PhantomData<H>,
    _marker_prf: std::marker::PhantomData<PRF>,
}

pub struct LamportSignature<H: OneWay> {
    opened: [H::Domain; MSG_LENGTH * 8],
    unopened: [H::Domain; MSG_LENGTH * 8],
}

impl<H: OneWay, PRF: Pseudorandom> OneTimeSignatureScheme for Lamport<H, PRF>
where
    PRF::Output: Into<H::Domain>,
{
    type PublicKey = H::Domain; // the hash of 256 * 2 hashes

    type SecretKey = PRF::Key;

    type Signature = LamportSignature<H>; // 256 pre-images + the hashes of the ones we do not open

    type Digest = [u8; MSG_LENGTH];

    fn gen<R: Rng>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey) {
        // the secret key consists of two arrays of 256 random inputs
        // but we generate it from a PRF
        let sk = PRF::gen(rng);

        // expand the secret key
        let expanded_sk: [H::Domain; MSG_LENGTH * 8 * 2] =
            std::array::from_fn(|i| PRF::apply(&sk, i as u64).into());

        // for each secret key component, apply the function
        // to get the public key component
        let pre_pk: [H::Domain; MSG_LENGTH * 8 * 2] =
            std::array::from_fn(|i| H::apply(&expanded_sk[i..=i]));

        // now compress the pre_pk
        let pk = H::apply(&pre_pk);

        (pk, sk)
    }

    fn sign(sk: &Self::SecretKey, digest: &Self::Digest) -> Self::Signature {
        let mut opened: [H::Domain; MSG_LENGTH * 8] = [H::Domain::default(); MSG_LENGTH * 8];
        let mut unopened: [H::Domain; MSG_LENGTH * 8] = [H::Domain::default(); MSG_LENGTH * 8];

        // expand the secret key
        let expanded_sk: [H::Domain; MSG_LENGTH * 8 * 2] =
            std::array::from_fn(|i| PRF::apply(&sk, i as u64).into());

        // iterate through the bits of the message
        for (byte_index, byte) in digest.iter().enumerate() {
            for bit_index in 0..8 {
                // Shift and mask to get each bit
                let bit = (byte >> (7 - bit_index)) & 1;

                // open for bit and include hash for 1 - bit
                let index = byte_index * 8 + bit_index;
                let opened_idx = 2 * index + (bit as usize);
                let unopened_idx = 2 * index + ((1 - bit) as usize);
                opened[index] = expanded_sk[opened_idx];
                unopened[index] = H::apply(&expanded_sk[unopened_idx..=unopened_idx]);
            }
        }

        LamportSignature { opened, unopened }
    }

    fn verify(pk: &Self::PublicKey, digest: &Self::Digest, sig: &Self::Signature) -> bool {
        let mut pre_pk: [H::Domain; MSG_LENGTH * 8 * 2] =
            [H::Domain::default(); MSG_LENGTH * 8 * 2];

        // iterate through the bits of the message and recompute the pre_pk
        for (byte_index, byte) in digest.iter().enumerate() {
            for bit_index in 0..8 {
                // Shift and mask to get each bit
                let bit = (byte >> (7 - bit_index)) & 1;

                // assume bit is opened, and the hash of 1 - bit is included
                let index = byte_index * 8 + bit_index;
                let opened_idx = 2 * index + (bit as usize);
                let unopened_idx = 2 * index + ((1 - bit) as usize);

                pre_pk[opened_idx] = H::apply(&sig.opened[index..=index]);
                pre_pk[unopened_idx] = sig.unopened[index];
            }
        }

        // check that compressing pre_pk results in pk
        *pk == H::apply(&pre_pk)
    }
}

/// Lamport instantiated with SHA-256
pub type LamportSha = Lamport<Sha256Hash, Sha256PRF>;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    pub use sha2::{Digest, Sha256};

    #[test]
    fn honest_signing_verification() {
        let mut rng = thread_rng();
        let (pk, sk) = LamportSha::gen(&mut rng);

        let message = b"Test message to sign";
        let digest = Sha256::digest(message);

        let signature = LamportSha::sign(&sk, &digest.into());

        let is_valid = LamportSha::verify(&pk, &digest.into(), &signature);
        assert!(
            is_valid,
            "The signature should be valid with correct keys and message."
        );
    }

    #[test]
    fn manipulated_signature_verification() {
        let mut rng = thread_rng();
        let (pk, sk) = LamportSha::gen(&mut rng);

        let message = b"Test message to sign";
        let digest = Sha256::digest(message);

        let mut signature = LamportSha::sign(&sk, &digest.into());

        // Manipulate one byte in the signature's opened field
        signature.opened[0][0] ^= 0xFF; // Flip all bits in the first byte of the first element

        let is_valid = LamportSha::verify(&pk, &digest.into(), &signature);
        assert!(
            !is_valid,
            "The signature should be invalid when a byte is manipulated."
        );
    }
}
