use bincode;
use serde::{Serialize, Deserialize};
use ring::digest;
use ring::signature::{Ed25519KeyPair, Signature, KeyPair, VerificationAlgorithm, EdDSAParameters};

use crate::crypto::hash::{Hashable, H256};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Transaction {
    pub msg: String,
}

impl Hashable for Transaction {
    fn hash(&self) -> H256 {
        let serialized = bincode::serialize(self).unwrap();
        digest::digest(&digest::SHA256, serialized.as_ref()).into()
    }
}

/// Create digital signature of a transaction
pub fn sign(t: &Transaction, key: &Ed25519KeyPair) -> Signature {
    key.sign(t.msg.as_bytes())
}

/// Verify digital signature of a transaction, using public key instead of secret key
pub fn verify(t: &Transaction, public_key: &<Ed25519KeyPair as KeyPair>::PublicKey, signature: &Signature) -> bool {
    let pk = untrusted::Input::from(public_key.as_ref());
    let msg = untrusted::Input::from(t.msg.as_ref());
    let sig = untrusted::Input::from(signature.as_ref());
    match EdDSAParameters.verify(pk, msg, sig) {
        Ok(_) => true,
        _ => false
    }
}

#[cfg(any(test, test_utilities))]
pub mod tests {
    use super::*;
    use crate::crypto::key_pair;
    use rand::thread_rng;
    use rand::distributions::Distribution;

    fn generate_random_str() -> String {
        let rng = thread_rng();
        rand::distributions::Alphanumeric.sample_iter(rng).take(10).collect()
    }

    pub fn generate_random_transaction() -> Transaction {
        Transaction {msg: generate_random_str()}
    }

    #[test]
    fn sign_verify() {
        let t = generate_random_transaction();
        let key = key_pair::random();
        let signature = sign(&t, &key);
        assert!(verify(&t, &(key.public_key()), &signature));
    }
}
