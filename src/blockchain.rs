use std::collections::HashMap;

use crate::block::Block;
use crate::crypto::hash::H256;

pub struct Blockchain {
    blocks: HashMap<H256, Block>,
    longest_hash: H256,
}

impl Blockchain {
    /// Create a new blockchain, only containing the genesis block
    pub fn new() -> Self {
        let genesis = Block::genesis();
        let longest_hash = genesis.get_hash();
        let mut map: HashMap<H256, Block> = HashMap::new();
        map.insert(genesis.get_hash(), genesis);
        Self {
            blocks: map,
            longest_hash: longest_hash
        }
    }

    /// Insert a block into blockchain
    pub fn insert(&mut self, block: &Block) {
        unimplemented!()
    }

    /// Get the last block's hash of the longest chain
    pub fn tip(&self) -> H256 {
        self.longest_hash.clone()
    }

    /// Get the last block's hash of the longest chain
    #[cfg(any(test, test_utilities))]
    pub fn all_blocks_in_longest_chain(&self) -> Vec<H256> {
        unimplemented!()
    }
}

#[cfg(any(test, test_utilities))]
mod tests {
    use super::*;
    use crate::block::test::generate_random_block;
    use crate::crypto::hash::Hashable;

    #[test]
    fn insert_one() {
        let blockchain = Blockchain::new();
        let genesis_hash = blockchain.tip();
        assert_eq!(&genesis_hash, &H256::from([0u8; 32]));
        // let block = generate_random_block(&genesis_hash);
        // blockchain.insert(&block);
        // assert_eq!(blockchain.tip(), block.hash());
    }
}
