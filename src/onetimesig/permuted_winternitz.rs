use crate::symmetric::{hashprf::Sha256PRF, sha::Sha256Hash};
use crate::symmetric::{OneWay, Pseudorandom};

use super::{
    winternitz::{
        isolate_w_bit_chunk, Winternitz, CHUNKS_PER_BYTE, MSG_LENGTH, NUM_CHAINS_MESSAGE,
        WINDOW_SIZE,
    },
    OneTimeSignatureScheme,
};

/// Aggressive variant of Beamy (i.e., not signing the permutation)
pub struct PermutedWinternitz<H: OneWay, PRF: Pseudorandom> {
    _marker_h: std::marker::PhantomData<H>,
    _marker_prf: std::marker::PhantomData<PRF>,
}

fn count_chunk_frequencies(digest: &[u8; MSG_LENGTH as usize]) -> Vec<u64> {
    let k = 1 << WINDOW_SIZE;
    let mut frequencies: Vec<u64> = vec![0u64; k];

    // iterate over the chunks and count
    for i in 0..NUM_CHAINS_MESSAGE as usize {
        // isolate the byte in which the chunk resides
        let byte_index = i / CHUNKS_PER_BYTE as usize;
        let byte = digest[byte_index];

        // isolate the chunk
        let chunk_index = i % CHUNKS_PER_BYTE as usize;
        let chunk = isolate_w_bit_chunk(byte, chunk_index, WINDOW_SIZE as usize);
        frequencies[chunk as usize] += 1;
    }

    frequencies
}

fn chunk_permutation(digest: &[u8; MSG_LENGTH as usize]) -> Vec<u8> {
    // we want to compute a permutation {0,...,k-1} -> {0,...,k-1}
    // for k = 2^{WINDOW_SIZE}. We want that the chunk that occurs
    // least often is mapped to 0, the second-least frequent to 1, and so on
    let k = 1 << WINDOW_SIZE;
    let mut permutation: Vec<u8> = vec![0u8; k];

    // Step 1: count frequencies
    let frequencies = count_chunk_frequencies(digest);

    // Step 2: Build the permutation
    // Note that we could use sorting, but we do not expect k to be very
    // large, so doing it in this k^2 way is probably fine for now
    let mut used = vec![false; k];
    for j in (0..k).rev() {
        // find j-th most frequent chunk, and assign j to it
        let jlfc = frequencies
            .iter()
            .enumerate()
            .filter(|&(chunk, _freq)| !used[chunk])
            .max_by_key(|&(_chunk, freq)| freq)
            .map(|(chunk, _freq)| chunk)
            .unwrap();
        used[jlfc] = true;
        permutation[jlfc] = j as u8;
    }

    permutation
}

fn apply_permutation(
    digest: &[u8; MSG_LENGTH as usize],
    permutation: &Vec<u8>,
) -> [u8; MSG_LENGTH as usize] {
    let mut normalized_digest: [u8; MSG_LENGTH as usize] = [0u8; MSG_LENGTH as usize];

    for i in 0..NUM_CHAINS_MESSAGE as usize {
        // isolate the byte in which the chunk resides
        let byte_index = i / CHUNKS_PER_BYTE as usize;
        let byte = digest[byte_index];

        // isolate the chunk
        let chunk_index = i % CHUNKS_PER_BYTE as usize;
        let chunk = isolate_w_bit_chunk(byte, chunk_index, WINDOW_SIZE as usize);

        // translate it according to the permutation
        let renamed_chunk = permutation[chunk as usize];

        // write into result
        normalized_digest[byte_index] |= renamed_chunk << (chunk_index * WINDOW_SIZE as usize);
    }

    normalized_digest
}

impl<H: OneWay, PRF: Pseudorandom> OneTimeSignatureScheme for PermutedWinternitz<H, PRF>
where
    PRF::Output: Into<H::Domain>,
{
    type PublicKey = <Winternitz<H, PRF> as OneTimeSignatureScheme>::PublicKey;

    type SecretKey = <Winternitz<H, PRF> as OneTimeSignatureScheme>::SecretKey;

    type Signature = <Winternitz<H, PRF> as OneTimeSignatureScheme>::Signature;

    type Digest = [u8; MSG_LENGTH as usize];

    fn gen<R: rand::Rng>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey) {
        // the key pair is as in Winternitz
        <Winternitz<H, PRF> as OneTimeSignatureScheme>::gen(rng)
    }

    fn rand_digest<R: rand::Rng>(rng: &mut R) -> Self::Digest {
        let mut digest = [0u8; MSG_LENGTH as usize];
        rng.fill_bytes(&mut digest);
        digest
    }

    fn sign(sk: &Self::SecretKey, digest: &Self::Digest) -> Self::Signature {
        // we first identify the digest-specific chunk permutation
        let permutation = chunk_permutation(digest);

        // then, we rename the chunks accordingly
        let normalized_digest = apply_permutation(digest, &permutation);

        // then, we sign with Winternitz
        <Winternitz<H, PRF> as OneTimeSignatureScheme>::sign(sk, &normalized_digest)
    }

    fn verify(pk: &Self::PublicKey, digest: &Self::Digest, sig: &Self::Signature) -> bool {
        // we first identify the digest-specific chunk permutation
        let permutation = chunk_permutation(digest);

        // then, we rename the chunks accordingly
        let normalized_digest = apply_permutation(digest, &permutation);

        // then, we verify with Winternitz
        <Winternitz<H, PRF> as OneTimeSignatureScheme>::verify(pk, &normalized_digest, sig)
    }
}

/// Beamy instantiated with SHA-256
pub type PermutedWinternitzSha = PermutedWinternitz<Sha256Hash, Sha256PRF>;

#[cfg(test)]
mod tests {
    use crate::onetimesig::test_templates::{
        _honest_signing_verification_template, _wrong_digest_verification_template,
    };

    use super::*;
    use rand::{seq::SliceRandom, thread_rng};
    pub use sha2::{Digest, Sha256};

    #[test]
    fn honest_signing_verification() {
        _honest_signing_verification_template::<PermutedWinternitzSha>();
    }

    #[test]
    fn wrong_digest_verification() {
        _wrong_digest_verification_template::<PermutedWinternitzSha>();
    }

    #[test]
    fn manipulated_signature_verification() {
        let mut rng = thread_rng();
        let (pk, sk) = PermutedWinternitzSha::gen(&mut rng);

        let message = b"Test message to sign";
        let digest = Sha256::digest(message);

        let mut signature = PermutedWinternitzSha::sign(&sk, &digest.into());

        // Manipulate one byte in the signature's opened field
        signature[0][0] ^= 0xFF; // Flip all bits in the first byte of the first element

        let is_valid = PermutedWinternitzSha::verify(&pk, &digest.into(), &signature);
        assert!(
            !is_valid,
            "The signature should be invalid when a byte is manipulated."
        );
    }

    #[test]
    fn test_permutation() {
        // In this test, we check that `chunk_permutation` works as expected
        // On the way, we also test `count_chunk_frequencies`

        // Define the 2-bit chunks with their frequencies
        let mut chunks = Vec::new();
        chunks.extend(vec![0b10; 44]); // 44 occurrences of '10' -> it should be assigned '11'
        chunks.extend(vec![0b01; 36]); // 36 occurrences of '01' -> it should be assigned '10'
        chunks.extend(vec![0b11; 28]); // 28 occurrences of '11' -> it should be assigned '01'
        chunks.extend(vec![0b00; 20]); // 20 occurrences of '00' -> it should be assigned '00'

        // Shuffle the chunks to randomize their order
        chunks.shuffle(&mut thread_rng());

        // Convert the 2-bit chunks into bytes
        let mut digest = [0u8; MSG_LENGTH as usize];
        for (i, chunk) in chunks.chunks(4).enumerate() {
            // Each byte is made up of 4 chunks, each 2 bits
            digest[i] = (chunk[0] << 6) | (chunk[1] << 4) | (chunk[2] << 2) | chunk[3];
        }

        // Now test count_chunk_frequencies
        let frequencies = count_chunk_frequencies(&digest);
        assert!(frequencies[0b00] == 20, "0b00 should have frequency 20");
        assert!(frequencies[0b01] == 36, "0b01 should have frequency 36");
        assert!(frequencies[0b10] == 44, "0b10 should have frequency 44");
        assert!(frequencies[0b11] == 28, "0b11 should have frequency 28");

        // Now test chunk_permutation
        let permutation = chunk_permutation(&digest);
        assert!(permutation[0b00] == 0b00, "0b00 should be mapped to 0b00");
        assert!(permutation[0b01] == 0b10, "0b00 should be mapped to 0b00");
        assert!(permutation[0b10] == 0b11, "0b00 should be mapped to 0b00");
        assert!(permutation[0b11] == 0b01, "0b00 should be mapped to 0b00");
    }
}
