use serde::{Serialize, Deserialize};
use crate::crypto::hash::{H256, Hashable};
use crate::transaction::Transaction;

#[derive(Serialize, Deserialize, Debug)]
pub struct Block {
    hash: H256,         // the hash of the header in this block
    index: usize,       // the distance from the genesis block
    header: Header,
    content: Content,   // transaction in this block
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Header {
    parent: H256,
    nonce: u32,
    difficulty: H256,
    timestamp: usize,
    merkle_root: H256,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Content {
    trans: Vec<Transaction>
}

impl Hashable for Block {
    fn hash(&self) -> H256 {
        unimplemented!()
    }
}

#[cfg(any(test, test_utilities))]
pub mod test {
    use super::*;
    use crate::crypto::hash::H256;

    pub fn generate_random_block(parent: &H256) -> Block {
        unimplemented!()
    }
}
