use hex;
use ring::digest;
use serde::{Serialize, Deserialize};
use chrono::prelude::DateTime;
use chrono::Utc;
use std::time::{UNIX_EPOCH, Duration};
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

#[derive(Serialize, Deserialize)]
pub struct PrintableBlock {
    pub hash: String,
    pub parent_hash: String,
    pub index: usize,
    pub nonce: u32,
    pub difficulty: String,
    pub timestamp: String,
    pub merkle_root: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Header {
    pub parent: H256,
    pub nonce: u32,
    pub difficulty: H256,
    timestamp: u64,
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

impl PartialEq<Block> for Block {
    fn eq(&self, other: &Block) -> bool {
        let self_serialized_array = bincode::serialize(&self).unwrap();
        let other_serialized_array = bincode::serialize(other).unwrap();
        self_serialized_array == other_serialized_array
    }
}

static DIFFICULTY: i32 = 12; // number of leading zero

impl Block {
    pub fn genesis() -> Self {
        let h: [u8; 32] = [0; 32];
        let difficulty: [u8; 32] = set_difficulty(DIFFICULTY);

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

impl PrintableBlock {
    pub fn from_block_vec(blocks: &Vec<Block>) -> Vec<PrintableBlock> {
        let mut pblocks = Vec::<PrintableBlock>::new();
        for b in blocks {
            let t = UNIX_EPOCH + Duration::from_millis(b.header.timestamp);
            let datetime = DateTime::<Utc>::from(t);
            let ts_str = datetime.format("%Y-%m-%d %H:%M:%S%.3f").to_string();
            let p = PrintableBlock {
                hash: hex::encode(&b.hash),
                parent_hash: hex::encode(&b.header.parent),
                index: b.index,
                nonce: b.header.nonce,
                difficulty: hex::encode(&b.header.difficulty),
                timestamp: ts_str,
                merkle_root: hex::encode(&b.header.merkle_root),
            };
            pblocks.push(p);
        }
        pblocks
    }
}

impl Header {
    pub fn new( parent: &H256, nonce: u32, timestamp: u128,
                difficulty: &H256, merkle_root: &H256) -> Self {
        Self {
            parent: parent.clone(),
            nonce: nonce,
            difficulty: difficulty.clone(),
            timestamp: timestamp as u64,
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

    pub fn change_nonce(&mut self) {
        self.nonce = self.nonce.overflowing_add(1).0;
    }
}

impl Content {
    pub fn new() -> Self {
        Self {
            trans: Vec::<Transaction>::new(),
        }
    }

    pub fn new_with_trans(trans: &Vec<Transaction>) -> Self {
        Self {
            trans: trans.clone(),
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

fn set_difficulty(mut zero_cnt: i32) -> [u8; 32] {
    let mut difficulty : [u8; 32] = [std::u8::MAX; 32];

    for i in 0..32 {
        if zero_cnt <= 0 {break}

        if zero_cnt < 8 {
            difficulty[i] = 0xffu8 >> zero_cnt;
        } else {
            difficulty[i] = 0u8;
        }
        zero_cnt -= 8;
    }
    difficulty
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
        let timestamp: u128 = rng.gen();
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
        assert!(DIFFICULTY < 256);
        assert_eq!(0, array[0]);
        assert_eq!(15, array[1]);
        assert_eq!(255, array[2]);
        assert_eq!(255, array[30]);
        assert_eq!(255, array[31]);
    }

    #[test]
    fn test_content_new_with_trans() {
        let mut trans = Vec::<Transaction>::new();
        for _ in 0..3 {
            trans.push(generate_random_transaction());
        }
        let _content = Content::new_with_trans(&trans);
    }

    #[test]
    fn test_difficulty() {
        let test_array1 = set_difficulty(8);
        assert_eq!(0, test_array1[0]);
        assert_eq!(255, test_array1[1]);
        assert_eq!(255, test_array1[31]);

        let test_array1 = set_difficulty(9);
        assert_eq!(0, test_array1[0]);
        assert_eq!(0x7f, test_array1[1]);
        assert_eq!(255, test_array1[31]);

        let test_array2 = set_difficulty(10);
        assert_eq!(0, test_array2[0]);
        assert_eq!(63, test_array2[1]);
        assert_eq!(255, test_array2[2]);

        let test_array3 = set_difficulty(15);
        assert_eq!(0, test_array3[0]);
        assert_eq!(1, test_array3[1]);
        assert_eq!(0, test_array3[0]);
        assert_eq!(255, test_array1[31]);

        let test_array4 = set_difficulty(21);
        assert_eq!(0, test_array4[0]);
        assert_eq!(0, test_array4[1]);
        assert_eq!(7, test_array4[2]);
    }

    #[test]
    fn test_block_equality() {
        let rand_1: [u8; 32] = [0; 32];
        let rand_2: [u8; 32] = [1; 32];

        let content_1 = generate_random_content();
        let content_2 = generate_random_content();
        let header_1 = generate_random_header(&rand_1.into(), &content_1);
        let header_2 = generate_random_header(&rand_1.into(), &content_2);
        let header_3 = generate_random_header(&rand_2.into(), &content_1);

        let block_1 = Block::new(header_1.clone(), content_1.clone());
        let block_2 = Block::new(header_2.clone(), content_1.clone());
        let block_3 = Block::new(header_3.clone(), content_1.clone());
        let block_4 = Block::new(header_1.clone(), content_2.clone());
        let block_5 = Block::new(header_1.clone(), content_1.clone());

        // different header
        assert_ne!(block_1, block_2);
        assert_ne!(block_1, block_3);
        // different content
        assert_ne!(block_1, block_4);
        // same
        assert_eq!(block_1, block_5);
    }
}
