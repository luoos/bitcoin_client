use bincode;
use serde::{Serialize, Deserialize};
use ring::digest;
use ring::signature::{Ed25519KeyPair, Signature, KeyPair, VerificationAlgorithm, EdDSAParameters};

use crate::crypto::hash::{Hashable, H256, H160};

///UTXO model transaction
#[derive(Eq, PartialEq, Serialize, Deserialize, Debug, Default, Clone)]
pub struct SignedTransaction {
    pub transaction: Transaction,
    pub hash: H256,
    pub signature: Box<[u8]>,
    pub public_key: Box<[u8]>,
}

#[derive(Eq, PartialEq, Serialize, Deserialize, Debug, Default, Clone)]
pub struct Transaction {
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
}

#[derive(Eq, PartialEq, Serialize, Deserialize, Debug, Default, Clone)]
pub struct TxInput {
    pub pre_hash: H256, // Hash of previous transaction
    pub index: u32,   // Index in previous transaction's outputs vector
}

#[derive(Eq, PartialEq, Serialize, Deserialize, Debug, Default, Clone)]
pub struct TxOutput {
    pub rec_address: H160, // Recipient's address
    pub val: u64,        // Number of coin to transfer
}

impl Hashable for SignedTransaction {
    fn hash(&self) -> H256 { self.hash.clone() }
}

impl Hashable for Transaction {
    fn hash(&self) -> H256 {
        let serialized = bincode::serialize(self).unwrap();
        digest::digest(&digest::SHA256, serialized.as_ref()).into()
    }
}

impl SignedTransaction {
    pub fn new(transaction: Transaction, signature: Box<[u8]>, public_key: Box<[u8]>) -> Self {
        Self {
            transaction: transaction.clone(),
            hash: transaction.hash(),
            signature,
            public_key,
        }
    }

    // Call verify directly
    pub fn sign_check(&self) -> bool {
        verify(&self.transaction, self.public_key.as_ref(), self.signature.as_ref())
    }
}

impl TxInput {
    pub fn new(pre_hash: H256, index: u32) -> Self {
        Self {
            pre_hash,
            index,
        }
    }
}

impl TxOutput {
    pub fn new(rec_address: H160, val: u64) -> Self {
        Self {
            rec_address,
            val,
        }
    }
}

/// Create digital signature of a transaction
pub fn sign(t: &Transaction, key: &Ed25519KeyPair) -> Signature {
    let bytes = bincode::serialize(&t).unwrap();
    key.sign(bytes.as_ref())
}

/// Verify digital signature of a transaction, using public key instead of secret key (with bytes)
pub fn verify(t: &Transaction, public_key: &[u8], signature: &[u8]) -> bool {
    let bytes = bincode::serialize(&t).unwrap();
    let msg = untrusted::Input::from(bytes.as_ref());
    let pk = untrusted::Input::from(public_key);
    let sig = untrusted::Input::from(signature);
    match EdDSAParameters.verify(pk, msg, sig) {
        Ok(_) => true,
        _ => false
    }
}

/// Verify digital signature of a transaction, using public key instead of secret key (with origin type)
pub fn verify_with_origin_type(t: &Transaction, public_key: &<Ed25519KeyPair as KeyPair>::PublicKey, signature: &Signature) -> bool {
    let bytes = bincode::serialize(&t).unwrap();
    let msg = untrusted::Input::from(bytes.as_ref());
    let pk = untrusted::Input::from(public_key.as_ref());
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
    use crate::helper::*;

    #[test]
    fn test_sign_verify() {
        let t = generate_random_transaction();
        let t_2 = generate_random_transaction();
        let key = key_pair::random();
        let key_2 = key_pair::random();
        let signature = sign(&t, &key);
        let signature_2 = sign(&t_2, &key);

        assert!(verify_with_origin_type(&t.clone(), &(key.public_key().clone()), &signature.clone()));
        assert!(!verify_with_origin_type(&t.clone(), &(key.public_key().clone()), &signature_2.clone()));

        let sig_bytes: Box<[u8]> = signature.as_ref().into();
        let key_bytes: Box<[u8]> = key.public_key().as_ref().into();
        let sig_bytes_2: Box<[u8]> = signature_2.as_ref().into();
        let key_bytes_2: Box<[u8]> = key_2.public_key().as_ref().into();
        let st = SignedTransaction::new(t.clone(), sig_bytes.clone(), key_bytes.clone());
        // SignedTransaction with fake signature
        let st_2 = SignedTransaction::new(t.clone(), sig_bytes_2.clone(), key_bytes.clone());

        assert_eq!(t.clone().inputs, st.clone().transaction.inputs);
        assert_eq!(t.clone().outputs, st.clone().transaction.outputs);

        assert!(verify(&st.transaction.clone(), st.public_key.clone().as_ref(), st.signature.clone().as_ref()));
        // Verify any one of three conditions mismatches, can't be approve
        assert!(!verify(&st.transaction.clone(), st.public_key.clone().as_ref(), st_2.signature.clone().as_ref()));
        assert!(!verify(&st.transaction.clone(), key_bytes_2.clone().as_ref(), st.signature.clone().as_ref()));
        assert!(!verify(&t_2.clone(), st.public_key.clone().as_ref(), st.signature.clone().as_ref()));
    }

    #[test]
    fn assignment2_transaction_1() {
        let t = generate_random_transaction();
        let key = key_pair::random();
        let signature = sign(&t, &key);
        assert!(verify_with_origin_type(&t, &(key.public_key()), &signature));
    }
    #[test]
    fn assignment2_transaction_2() {
        let t = generate_random_transaction();
        let key = key_pair::random();
        let signature = sign(&t, &key);
        let key_2 = key_pair::random();
        let t_2 = generate_random_transaction();
        assert!(!verify_with_origin_type(&t_2, &(key.public_key()), &signature));
        assert!(!verify_with_origin_type(&t, &(key_2.public_key()), &signature));
    }
}
