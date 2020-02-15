use ring::digest;
use serde::{Serialize, Deserialize};
use crate::crypto::hash::{H256, Hashable};
use crate::transaction::Transaction;
use crate::crypto::merkle::MerkleTree;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub hash: H256,         // the hash of the header in this block
    pub index: usize,       // the distance from the genesis block
    pub header: Header,
    content: Content,   // transaction in this block
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Header {
    pub parent: H256,
    pub nonce: u32,
    pub difficulty: H256,
    timestamp: usize,
    merkle_root: H256,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Content {
    trans: Vec<Transaction>
}

impl Hashable for Block {
    fn hash(&self) -> H256 {
        self.hash.clone()
    }
}

static DIFFICULTY: usize = 4; // number of leading zero

impl Block {
    pub fn genesis() -> Self {
        let h: [u8; 32] = [0; 32];
        let mut difficulty: [u8; 32] = [std::u8::MAX; 32];
        for i in 0..DIFFICULTY {
            difficulty[i] = 0;
        }
        let header = Header {
            parent: h.into(),
            nonce: 0,
            difficulty: difficulty.into(),
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

    pub fn new(header: Header, content: Content) -> Self {
        Self {
            hash: header.hash(),
            index: 0,
            header: header,
            content: content,
        }
    }

    pub fn get_hash(&self) -> H256 {
        self.hash.clone()
    }
}

impl Header {
    pub fn new( parent: &H256, nonce: u32, timestamp: usize,
                 difficulty: &H256, merkle_root: &H256) -> Self {
        Self {
            parent: parent.clone(),
            nonce: nonce,
            difficulty: difficulty.clone(),
            timestamp: timestamp,
            merkle_root: merkle_root.clone(),
        }
    }

    pub fn hash(&self) -> H256 {
        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(self.parent.as_ref());
        ctx.update(&self.nonce.to_be_bytes());
        ctx.update(self.difficulty.as_ref());
        ctx.update(&self.timestamp.to_be_bytes());
        ctx.update(self.merkle_root.as_ref());
        ctx.finish().into()
    }
}

impl Content {
    pub fn new() -> Self {
        Self {
            trans: Vec::<Transaction>::new(),
        }
    }

    pub fn add_tran(&mut self, tran: Transaction) {
        self.trans.push(tran);
    }

    pub fn merkle_root(&self) -> H256 {
        let tree = MerkleTree::new(&self.trans);
        tree.root()
    }
}

#[cfg(any(test, test_utilities))]
pub mod test {
    use super::*;
    use crate::crypto::hash::H256;
    use crate::transaction::tests::generate_random_transaction;
    use crate::crypto::hash::tests::generate_random_hash;
    use rand::Rng;

    pub fn generate_random_block(parent: &H256) -> Block {
        let content = generate_random_content();
        let header = generate_random_header(parent, &content);
        Block::new(header, content)
    }


    pub fn generate_random_header(parent: &H256, content: &Content) -> Header {
        let mut rng = rand::thread_rng();
        let nonce: u32 = rng.gen();
        let timestamp: usize = rng.gen();
        let difficulty = generate_random_hash();
        let merkle_root = content.merkle_root();
        Header::new(
            parent, nonce, timestamp,
            &difficulty, &merkle_root
        )
    }

    pub fn generate_random_content() -> Content {
        let mut content = Content::new();
        let mut rng = rand::thread_rng();
        let size: u32 = rng.gen_range(10, 20);
        for _ in 0..size {
            content.add_tran(generate_random_transaction());
        }
        content
    }

    #[test]
    fn test_genesis() {
        let g = Block::genesis();
        assert_eq!(0, g.index);
        assert_eq!(g.hash, H256::from([0u8; 32]));
        let array: [u8; 32] = g.header.difficulty.into();
        assert!(DIFFICULTY > 0);
        assert!(DIFFICULTY < 32);
        assert_eq!(0, array[0]);
        assert_eq!(0, array[DIFFICULTY-1]);
        assert_eq!(255, array[DIFFICULTY]);
    }
}
