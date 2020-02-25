use std::collections::{HashMap, HashSet};
use log::info;

use crate::block::{Block, Header};
use crate::crypto::hash::H256;

pub struct Blockchain {
    blocks: HashMap<H256, Block>,
    orphans: HashMap<H256, Vec<Block>>, // key is the hash of the parent
    orphans_hash: HashSet<H256>,  // hash of orphans
    longest_hash: H256,
    max_index: usize,
}

impl Blockchain {
    // Create a new blockchain, only containing the genesis block
    pub fn new() -> Self {
        let genesis = Block::genesis();
        let longest_hash = genesis.get_hash();
        let mut map: HashMap<H256, Block> = HashMap::new();
        let orphans: HashMap<H256, Vec<Block>> = HashMap::new();
        map.insert(genesis.get_hash(), genesis);
        Self {
            blocks: map,
            orphans: orphans,
            orphans_hash: HashSet::new(),
            longest_hash: longest_hash,
            max_index: 0,
        }
    }

    // Insert a block into blockchain
    pub fn insert(&mut self, block: &Block) -> bool {
        if self.exist(&block.hash) {
            return false;
        }
        let mut b = block.clone();
        let parent_hash = &b.header.parent;

        match self.blocks.get(parent_hash) {
            Some(prev_block) => {
                let cur_index = prev_block.index + 1;
                b.index = cur_index;
                let longest_block = self.blocks.get(&self.longest_hash).unwrap();
                if cur_index > longest_block.index {
                    self.longest_hash = b.hash.clone();
                    self.max_index = cur_index;
                }
                let new_parent_hash = b.hash.clone();
                info!("insert block with index {:?}: {:?}, nonce: {}, parent: {:?}",
                      &b.index, &b.hash, b.header.nonce, parent_hash);

                self.blocks.insert(b.hash.clone(), b);
                self.handle_orphan(&new_parent_hash);
            },
            None => {
                self.orphans_hash.insert(b.hash.clone());
                match self.orphans.get_mut(parent_hash) {
                    Some(children_vec) => {
                        children_vec.push(b);
                    },
                    None => {
                        let mut children_vec = Vec::<Block>::new();
                        let parent_hash_copy = parent_hash.clone();
                        children_vec.push(b);
                        self.orphans.insert(parent_hash_copy, children_vec);
                    }
                }
            }
        }
        return true;
    }

    fn handle_orphan(&mut self, new_parent: &H256) {
        if let Some(children_vec) = self.orphans.remove(new_parent) {
            for child in children_vec.iter() {
                self.orphans_hash.remove(&child.hash);
                self.insert(child);
            }
        }
    }

    // Get the last block's hash of the longest chain
    pub fn tip(&self) -> H256 {
        self.longest_hash.clone()
    }

    pub fn difficulty(&self) -> H256 {
        self.blocks.get(&self.longest_hash)
            .unwrap().header.difficulty.clone()
    }

    // include genesis block
    pub fn length(&self) -> usize {
        self.max_index + 1
    }

    // check existence, including orphans
    pub fn exist(&self, hash: &H256) -> bool {
        self.blocks.contains_key(hash)
            || self.orphans_hash.contains(hash)
    }

    pub fn get_blocks(&self, hashes: &Vec<H256>) -> Vec<Block> {
        let mut blocks = Vec::<Block>::new();
        for h in hashes.iter() {
            if let Some(b) = self.blocks.get(&h) {
                blocks.push(b.clone());
            }
        }
        blocks
    }

    pub fn get_block(&self, hash: &H256) -> Block {
        self.blocks.get(hash).unwrap().clone()
    }

    pub fn hash_chain(&self) -> Vec<H256> {
        let mut cur_hash = self.tip();
        let mut cur_block = self.blocks.get(&cur_hash).unwrap();
        let mut index = cur_block.index as i32;
        let mut result = Vec::<H256>::new();
        while index >= 0 {
            result.push(cur_hash);
            cur_hash = cur_block.header.parent.clone();
            cur_block = self.blocks.get(&cur_hash).unwrap();
            index -= 1;
        }
        result.reverse();
        result
    }

    pub fn header_chain(&self) -> Vec<Header> {
        let hash_chain = self.hash_chain();
        let header_chain = hash_chain.iter()
                .map(|h| self.get_block(h).header.clone())
                .collect();
        header_chain
    }

    pub fn block_chain(&self) -> Vec<Block> {
        let hash_chain = self.hash_chain();
        let block_chain = hash_chain.iter()
                .map(|h| self.get_block(h).clone())
                .collect();
        block_chain
    }

    // Get the last block's hash of the longest chain
    #[cfg(any(test, test_utilities))]
    pub fn all_blocks_in_longest_chain(&self) -> Vec<H256> {
        let mut cur_hash = self.tip();
        let mut cur_block = self.blocks.get(&cur_hash).unwrap();
        let mut index = cur_block.index as i32;
        let mut result = Vec::<H256>::new();
        while index >= 0 {
            result.push(cur_hash);
            cur_hash = cur_block.header.parent.clone();
            cur_block = self.blocks.get(&cur_hash).unwrap();
            index -= 1;
        }
        result
    }
}

#[cfg(any(test, test_utilities))]
mod tests {
    use super::*;
    use crate::block::test::generate_random_block;
    use crate::crypto::hash::Hashable;

    #[test]
    fn insert_one() {
        let mut blockchain = Blockchain::new();
        let genesis_hash = blockchain.tip();
        assert_eq!(&genesis_hash, &H256::from([0u8; 32]));
        let block = generate_random_block(&genesis_hash);
        assert!(blockchain.insert(&block));
        assert_eq!(blockchain.tip(), block.hash());
        assert_eq!(blockchain.difficulty(), block.header.difficulty);
        assert!(!blockchain.insert(&block));
    }

    #[test]
    fn switch_tip() {
        /*
         * structure:
         * genesis <- block_1_1 <- block_1_2 <- block_1_3 <- block_1_4
         *              ^
         *              ---------  block_2_1 <- block_2_2
         */
        let mut blockchain = Blockchain::new();
        let genesis_hash = blockchain.tip();
        let block_1_1 = generate_random_block(&genesis_hash);
        blockchain.insert(&block_1_1);
        let block_1_2 = generate_random_block(&block_1_1.hash());
        blockchain.insert(&block_1_2);
        assert_eq!(blockchain.tip(), block_1_2.hash());
        let block_2_1 = generate_random_block(&block_1_1.hash());
        blockchain.insert(&block_2_1);
        assert_eq!(blockchain.tip(), block_1_2.hash());
        let block_2_2 = generate_random_block(&block_2_1.hash());
        blockchain.insert(&block_2_2);
        assert_eq!(blockchain.tip(), block_2_2.hash());
        let block_1_3 = generate_random_block(&block_1_2.hash());
        blockchain.insert(&block_1_3);
        assert_eq!(blockchain.tip(), block_2_2.hash());
        let block_1_4 = generate_random_block(&block_1_3.hash());
        blockchain.insert(&block_1_4);
        assert_eq!(blockchain.tip(), block_1_4.hash());
    }

    #[test]
    fn handle_orphan() {
        let mut blockchain = Blockchain::new();
        let genesis_hash = blockchain.tip();
        assert_eq!(1, blockchain.length());
        let block1 = generate_random_block(&genesis_hash);
        let block2 = generate_random_block(&block1.hash());
        let block3 = generate_random_block(&block2.hash());
        blockchain.insert(&block3);
        blockchain.insert(&block2);
        blockchain.insert(&block1);
        assert_eq!(blockchain.tip(), block3.hash());
        assert_eq!(4, blockchain.length());

        // naming rule: block_<branch>_<index>
        let mut blockchain = Blockchain::new();
        let genesis_hash = blockchain.tip();
        let block_1_1 = generate_random_block(&genesis_hash);
        let block_1_2 = generate_random_block(&block_1_1.hash());
        let block_1_3 = generate_random_block(&block_1_2.hash());
        let block_2_2 = generate_random_block(&block_1_1.hash());
        let block_2_3 = generate_random_block(&block_2_2.hash());
        let block_2_4 = generate_random_block(&block_2_3.hash());
        let block_2_5 = generate_random_block(&block_2_4.hash());
        blockchain.insert(&block_2_5);
        blockchain.insert(&block_2_4);
        blockchain.insert(&block_2_3);
        blockchain.insert(&block_2_2);
        blockchain.insert(&block_1_3);
        blockchain.insert(&block_1_2);
        assert_eq!(blockchain.tip(), genesis_hash);
        blockchain.insert(&block_1_1);
        assert_eq!(blockchain.tip(), block_2_5.hash());
        assert_eq!(6, blockchain.length());
    }

    #[test]
    fn longest_chain_hash() {
        let mut blockchain = Blockchain::new();
        let genesis_hash = blockchain.tip();
        let block1 = generate_random_block(&genesis_hash);
        let block2 = generate_random_block(&block1.hash());
        let block3 = generate_random_block(&block2.hash());
        blockchain.insert(&block3);
        blockchain.insert(&block2);
        blockchain.insert(&block1);
        assert_eq!(blockchain.tip(), block3.hash());
        let chain_hash = blockchain.all_blocks_in_longest_chain();
        assert_eq!(chain_hash[0], block3.hash);
        assert_eq!(chain_hash.last().unwrap(), &genesis_hash);
    }

    #[test]
    fn test_exist() {
        let mut blockchain = Blockchain::new();
        let genesis_hash = blockchain.tip();
        assert!(blockchain.exist(&genesis_hash));
        let block1 = generate_random_block(&genesis_hash);
        let block2 = generate_random_block(&block1.hash());
        let block3 = generate_random_block(&block2.hash());
        assert!(!blockchain.exist(&block3.hash));
        blockchain.insert(&block3);
        assert!(blockchain.exist(&block3.hash));
        assert!(!blockchain.exist(&block1.hash));
        blockchain.insert(&block1);
        assert!(blockchain.exist(&block1.hash));
    }

    #[test]
    fn test_get_blocks() {
        let mut blockchain = Blockchain::new();
        let genesis_hash = blockchain.tip();
        let block1 = generate_random_block(&genesis_hash);
        let block2 = generate_random_block(&block1.hash);
        let block3 = generate_random_block(&block2.hash);
        blockchain.insert(&block1);
        blockchain.insert(&block2);
        let hashes = vec![block1.hash(), block2.hash(), block3.hash()];
        let blocks = blockchain.get_blocks(&hashes);
        assert_eq!(2, blocks.len());
        assert_eq!(&block1.hash, &blocks[0].hash);
        assert_eq!(&block2.hash, &blocks[1].hash);
    }

    #[test]
    fn test_get_hash_chain() {
        let mut blockchain = Blockchain::new();
        let genesis_hash = blockchain.tip();
        let block1 = generate_random_block(&genesis_hash);
        let block2 = generate_random_block(&block1.hash);
        let block3 = generate_random_block(&block2.hash);
        blockchain.insert(&block1);
        blockchain.insert(&block2);
        blockchain.insert(&block3);
        let hashes = blockchain.hash_chain();
        assert_eq!(genesis_hash, hashes[0]);
        assert_eq!(block1.hash, hashes[1]);
        assert_eq!(block2.hash, hashes[2]);
        assert_eq!(block3.hash, hashes[3]);
    }

    #[test]
    fn test_get_header_chain() {
        let mut blockchain = Blockchain::new();
        let genesis_hash = blockchain.tip();
        let block1 = generate_random_block(&genesis_hash);
        let block2 = generate_random_block(&block1.hash);
        let block3 = generate_random_block(&block2.hash);
        blockchain.insert(&block1);
        blockchain.insert(&block2);
        blockchain.insert(&block3);
        let headers = blockchain.header_chain();
        assert_eq!(genesis_hash, headers[1].parent);
        assert_eq!(block1.hash, headers[2].parent);
        assert_eq!(block2.hash, headers[3].parent);
    }

    #[test]
    fn test_get_block_chain() {
        let mut blockchain = Blockchain::new();
        let genesis_hash = blockchain.tip();
        let block1 = generate_random_block(&genesis_hash);
        let block2 = generate_random_block(&block1.hash);
        let block3 = generate_random_block(&block2.hash);
        blockchain.insert(&block1);
        blockchain.insert(&block2);
        blockchain.insert(&block3);
        let blocks = blockchain.block_chain();
        assert_eq!(block1.hash, blocks[1].hash);
        assert_eq!(block2.hash, blocks[2].hash);
        assert_eq!(block3.hash, blocks[3].hash);
    }
}
