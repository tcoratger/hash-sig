use rand::Rng;

use crate::{onetimesig::{lamport::LamportSha, OneTimeSignatureScheme}, symmetric::{hashtree::{Sha256HashTree, WIDTH}, VectorCommitment}};

/// Trait to model an indexed signature scheme.
/// In such a scheme, we sign with respect to slots/indices.
/// We assume each we sign for each slot/index only once.
pub trait IndexedSignatureScheme {
    type PublicKey;
    type SecretKey;
    type Signature;
    type Digest;

    /// Generates a new key pair, returning the public and private keys.
    fn gen<R: Rng>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey);

    /// Generates a random digest (e.g., used for test purposes)
    fn rand_digest<R: Rng>(rng: &mut R) -> Self::Digest;

    /// Signs a message (given by its digest) and returns the signature.
    /// The signature is with respect to a given index.
    fn sign(sk: &Self::SecretKey, index: u64, digest: &Self::Digest) -> Self::Signature;

    /// Verifies a signature with respect to public key, index, and message digest.
    fn verify(
        pk: &Self::PublicKey,
        index: u64,
        digest: &Self::Digest,
        sig: &Self::Signature,
    ) -> bool;
}

/// Lifetime of a key for OTSBasedIndexedSignatureScheme.
/// This is the number of indices that are supported.
/// Note: not so nice that this is currently using a constant
/// from hashtree.rs, as it is no longer fully generic.
/// Need to figure out a better way of doing it later.
const SIG_KEY_LIFETIME: usize = WIDTH;

/// This implements an indexed signature scheme from any one time signature scheme
/// and a vector commitment. E.g., Lamport + Merkle tree.
pub struct OTSBasedIndexedSignatureScheme<OTS: OneTimeSignatureScheme, VC: VectorCommitment> {
    _marker_ots: std::marker::PhantomData<OTS>,
    _marker_vc: std::marker::PhantomData<VC>,
}

/// Signature for OTSBasedIndexedSignatureScheme. It contains a
/// one time public key, an opening for the vector commitment, and a one time signature.
pub struct OTSBasedIndexedSignature<OTS: OneTimeSignatureScheme, VC: VectorCommitment> {
    one_time_key: OTS::PublicKey,
    vc_opening: VC::Opening,
    one_time_signature: OTS::Signature,
}

pub struct OTSBasedIndexedSecretKey<OTS: OneTimeSignatureScheme, VC: VectorCommitment> {
    one_time_secret_keys: Vec<OTS::SecretKey>,
    one_time_public_keys: Vec<OTS::PublicKey>,
    one_time_public_keys_domain: Vec<VC::Domain>,
}

impl<OTS: OneTimeSignatureScheme, VC: VectorCommitment> IndexedSignatureScheme
    for OTSBasedIndexedSignatureScheme<OTS, VC>
where
    OTS::PublicKey: Into<VC::Domain>,
    OTS::PublicKey: Clone,
{
    type PublicKey = VC::Commitment;

    type SecretKey = OTSBasedIndexedSecretKey<OTS, VC>;

    type Signature = OTSBasedIndexedSignature<OTS, VC>;

    type Digest = OTS::Digest;

    fn gen<R: Rng>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey) {
        // we generate one key pair per index
        let mut sk_vec = Vec::with_capacity(SIG_KEY_LIFETIME);
        let mut pk_vec = Vec::with_capacity(SIG_KEY_LIFETIME);
        let mut pk_vec_domain = Vec::with_capacity(SIG_KEY_LIFETIME);
        for _ in 0..SIG_KEY_LIFETIME {
            let (pk_index, sk_index) = OTS::gen(rng);
            sk_vec.push(sk_index);
            pk_vec.push(pk_index.clone());
            pk_vec_domain.push(pk_index.into());
        }

        // we commit to the public keys using the vector commitment to get the public key
        let pk = VC::commit(&pk_vec_domain[..]);

        // the public key is the commitment, the secret key is the list of all key pairs
        let sk = OTSBasedIndexedSecretKey {
            one_time_secret_keys: sk_vec,
            one_time_public_keys: pk_vec,
            one_time_public_keys_domain: pk_vec_domain,
        };
        (pk, sk)
    }

    fn rand_digest<R: Rng>(rng: &mut R) -> Self::Digest {
        OTS::rand_digest(rng)
    }

    fn sign(sk: &Self::SecretKey, index: u64, digest: &Self::Digest) -> Self::Signature {
        assert!(
            sk.one_time_secret_keys.len() >= SIG_KEY_LIFETIME,
            "secret key has to be long enough"
        );
        assert!(
            sk.one_time_public_keys.len() >= SIG_KEY_LIFETIME,
            "secret key has to be long enough"
        );
        assert!(
            sk.one_time_public_keys_domain.len() >= SIG_KEY_LIFETIME,
            "secret key has to be long enough"
        );

        // we sign using the one time secret key for that index
        let one_time_signature = OTS::sign(&sk.one_time_secret_keys[index as usize], digest);

        // we also need to give the public key to the verifier
        // Note: this could be easier if we had a pk_from_sk function
        let one_time_key = sk.one_time_public_keys[index as usize].clone();

        // we need to convince the verifier that the one_time_public_key is consistent
        // with our long time key. For that, we compute an opening and include it.
        let vc_opening = VC::open(&sk.one_time_public_keys_domain[..], index);

        OTSBasedIndexedSignature {
            one_time_key,
            vc_opening,
            one_time_signature,
        }
    }

    fn verify(
        pk: &Self::PublicKey,
        index: u64,
        digest: &Self::Digest,
        sig: &Self::Signature,
    ) -> bool {
        // first, we check that this is a valid one time signature
        if !OTS::verify(&sig.one_time_key, digest, &sig.one_time_signature) {
            return false;
        }

        // second, we should check that this one time key is consistent with the
        // long term public key. We do that by verifying the vector commitment opening.
        if !VC::verify(&pk, index, &sig.vc_opening) {
            return false;
        }

        // all checks have passed, so this is a valid signature
        true
    }
}



/// Instantiation of OTSBasedIndexedSignatureScheme using Merkle Trees + Lamport
pub type LamportIndexedSignatureScheme<> = OTSBasedIndexedSignatureScheme<LamportSha, Sha256HashTree>;


#[cfg(test)]
mod tests {
    use rand::thread_rng;


    use super::*;

    #[test]
    fn test_gen_sign_verify() {
        let mut rng = thread_rng();

        // generate a key pair
        let (pk, sk) = LamportIndexedSignatureScheme::gen(&mut rng);

        // for every index: sign and verify
        for _ in 0..1000 {
            // look at a random index
            let index = rng.gen_range(0..SIG_KEY_LIFETIME as u64);

            // sign a random digest
            let digest = LamportIndexedSignatureScheme::rand_digest(&mut rng);
            let sig = LamportIndexedSignatureScheme::sign(&sk, index, &digest);

            // signature should verify
            assert!(LamportIndexedSignatureScheme::verify(&pk, index, &digest, &sig));
        }
    }
}