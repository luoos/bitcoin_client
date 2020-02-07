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
        self.hash.clone()
    }
}

impl Block {
    pub fn genesis() -> Self {
        let h: [u8; 32] = [0; 32];
        let header = Header {
            parent: h.into(),
            nonce: 0,
            difficulty: h.into(),
            timestamp: 0,
            merkle_root: h.into(),
        };

        let content = Content {
            trans: Vec::<Transaction>::new(),
        };

        Block {
            hash: h.into(),
            index: 0,
            header: header,
            content: content,
        }
    }

    pub fn get_hash(&self) -> H256 {
        self.hash.clone()
    }
}

#[cfg(any(test, test_utilities))]
pub mod test {
    use super::*;
    use crate::crypto::hash::H256;

    pub fn generate_random_block(parent: &H256) -> Block {
        unimplemented!()
    }

    #[test]
    fn test_genesis() {
        let g = Block::genesis();
        assert_eq!(0, g.index);
        assert_eq!(g.hash, H256::from([0u8; 32]));
    }
}
