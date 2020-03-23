use std::collections::HashMap;
use log::info;

use crate::block::{Block, Header, Content, State};
use crate::crypto::hash::H256;

pub struct Blockchain {
    blocks: HashMap<H256, Block>,
    orphans_map: HashMap<H256, Vec<Block>>, // key is the hash of the parent
    orphans: HashMap<H256, Block>,
    longest_hash: H256,
    max_index: usize,
    difficulty: H256,  // assume difficulty is consistent
    states: HashMap<H256, State>,
    check_trans: bool,  // can only be false in test
}

impl Blockchain {
    // Create a new blockchain, only containing the genesis block
    pub fn new() -> Self {
        let genesis = Block::genesis();
        let genesis_hash = genesis.hash.clone();
        let difficulty = genesis.header.difficulty.clone();
        let longest_hash = genesis.get_hash();
        let mut map: HashMap<H256, Block> = HashMap::new();
        let orphans_map: HashMap<H256, Vec<Block>> = HashMap::new();
        map.insert(genesis.get_hash(), genesis);
        let mut states: HashMap<H256, State> = HashMap::new();
        let genesis_state = State::new();
        states.insert(genesis_hash, genesis_state);
        Self {
            blocks: map,
            orphans_map,
            orphans: HashMap::new(),
            longest_hash,
            max_index: 0,
            difficulty,
            states,
            check_trans: true,
        }
    }

    // Insert a block with existence & validation check (used in inter-miner blocks broadcast)
    pub fn insert_with_check(&mut self, block: &Block) -> bool {
        if self.exist(&block.hash) || !self.validate_block_meta(block) {
            return false;
        }
        return self.insert(block);
    }

    // Insert a block into blockchain if parent exists; otherwise, put it into orphan buffer
    pub fn insert(&mut self, block: &Block) -> bool {
        let mut b = block.clone();
        let parent_hash = &b.header.parent;

        match self.blocks.get(parent_hash) {
            Some(prev_block) => {
                // validate transaction and generate new state
                if let Some(new_state) = self.try_generate_new_state(block) {
                    self.states.insert(block.hash.clone(), new_state);
                } else {
                    return false;
                }
                let cur_index = prev_block.index + 1;
                b.index = cur_index;
                let longest_block = self.blocks.get(&self.longest_hash).unwrap();
                if cur_index > longest_block.index {
                    self.longest_hash = b.hash.clone();
                    self.max_index = cur_index;
                }
                let new_parent_hash = b.hash.clone();
                info!("Insert block with index {:?}: {:?}, nonce: {}, parent: {:?}",
                      &b.index, &b.hash, b.header.nonce, parent_hash);

                self.blocks.insert(b.hash.clone(), b);
                info!("Total number of blocks is {:?}, Length of longest chain is {:?}", self.blocks.len(), self.length());

                self.handle_orphan(&new_parent_hash);
            },
            None => {
                self.orphans.insert(b.hash.clone(), b.clone());
                match self.orphans_map.get_mut(parent_hash) {
                    Some(children_vec) => {
                        children_vec.push(b);
                    },
                    None => {
                        let mut children_vec = Vec::<Block>::new();
                        let parent_hash_copy = parent_hash.clone();
                        children_vec.push(b);
                        self.orphans_map.insert(parent_hash_copy, children_vec);
                    }
                }
            }
        }
        return true;
    }

    // Deal with a newly-arrived parent block's orphans
    fn handle_orphan(&mut self, new_parent: &H256) {
        if let Some(children_vec) = self.orphans_map.remove(new_parent) {
            for child in children_vec.iter() {
                self.orphans.remove(&child.hash);
                self.insert(child);
            }
        }
    }

    // Check if a block is orphan
    pub fn is_orphan(&self, hash: &H256) -> bool {
        self.orphans.contains_key(hash)
    }

    // Trace back the very-first missing block of a block's hash
    pub fn missing_parent(&self, orphan_hash: &H256) -> Option<H256> {
        if !self.is_orphan(orphan_hash) {
            return None
        }
        let mut cur = orphan_hash;
        while self.orphans.contains_key(&cur) {
            cur = &self.orphans.get(cur).unwrap().header.parent;
        }
        Some(cur.clone())
    }

    // Try to create new state for the new block
    pub fn try_generate_new_state(&self, block: &Block) -> Option<State> {
        if !self.check_trans {
            return Some(State::new());  // skip in test
        }
        let parent_state = self.states.get(&block.header.parent).unwrap();
        return block.try_generate_state(parent_state);
    }

    // Perform validation checks on PoW & difficulty & all transactions within it
    pub fn validate_block_meta(&self, block: &Block) -> bool {
        let header_hash = block.header.hash();
        if header_hash == block.hash
            && block.header.difficulty == self.difficulty
            && header_hash < self.difficulty
            && block.validate_signature() {
            return true;
        }
        return false;
    }

    // Get the last block's hash of the longest chain
    pub fn tip(&self) -> H256 {
        self.longest_hash.clone()
    }

    pub fn tip_block_state(&self) -> State {
        self.states.get(&self.longest_hash).unwrap().clone()
    }

    // include genesis block
    pub fn length(&self) -> usize {
        self.max_index + 1
    }

    pub fn difficulty(&self) -> H256 {
        self.difficulty.clone()
    }

    // check existence, including orphans_map
    pub fn exist(&self, hash: &H256) -> bool {
        self.blocks.contains_key(hash)
            || self.orphans.contains_key(hash)
    }

    // Given hashes, get blocks from chain & orphan buffer
    pub fn get_blocks(&self, hashes: &Vec<H256>) -> Vec<Block> {
        let mut blocks = Vec::<Block>::new();
        for h in hashes.iter() {
            if let Some(b) = self.blocks.get(&h) {
                blocks.push(b.clone());
            } else if let Some(b) = self.orphans.get(&h) {
                blocks.push(b.clone());
            }
        }
        blocks
    }

    // Given hash, get a block from chain or orphan buffer
    pub fn get_block(&self, hash: &H256) -> Option<Block> {
        if let Some(b) = self.blocks.get(hash) {
            Some(b.clone())
        } else if let Some(b) = self.orphans.get(hash) {
            Some(b.clone())
        } else {
            None
        }
    }

    // Get a vector of hashes in longest-chain from tip to genesis
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
        result
    }

    // Get a vector of headers in longest-chain from tip to genesis
    pub fn header_chain(&self) -> Vec<Header> {
        let hash_chain = self.hash_chain();
        let header_chain = hash_chain.iter()
                .map(|h| self.get_block(h).unwrap().header.clone())
                .collect();
        header_chain
    }

    // Get a vector of blocks in longest-chain from tip to genesis
    pub fn block_chain(&self) -> Vec<Block> {
        let hash_chain = self.hash_chain();
        let block_chain = hash_chain.iter()
                .map(|h| self.get_block(h).unwrap().clone())
                .collect();
        block_chain
    }

    // Get a vector of contents in longest-chain from tip to genesis
    pub fn content_chain(&self) -> Vec<Content> {
        let hash_chain = self.hash_chain();
        let content_chain = hash_chain.iter()
                .map(|h| self.get_block(h).unwrap().content)
                .collect();
        content_chain
    }

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

    pub fn change_difficulty(&mut self, difficulty: &H256) {
        self.difficulty = difficulty.clone();
    }

    #[cfg(any(test, test_utilities))]
    fn tip_difficulty(&self) -> H256 {
        self.blocks.get(&self.longest_hash)
            .unwrap().header.difficulty.clone()
    }

    #[cfg(any(test, test_utilities))]
    pub fn set_check_trans(&mut self, b: bool) {
        self.check_trans = b;
    }
}

#[cfg(any(test, test_utilities))]
mod tests {
    use super::*;
    use crate::crypto::hash::Hashable;
    use crate::helper::*;
    use crate::crypto::key_pair;
    use crate::network::message::Message;

    use std::net::{SocketAddr, IpAddr, Ipv4Addr};
    use std::time;
    use std::thread;

    #[test]
    fn test_insert() {
        let mut blockchain = Blockchain::new();
        blockchain.set_check_trans(false);
        let genesis_hash = blockchain.tip();
        assert_eq!(&genesis_hash, &H256::from([0u8; 32]));
        let block = generate_random_block(&genesis_hash);
        blockchain.insert(&block);
        assert_eq!(blockchain.tip(), block.hash());
        assert_eq!(blockchain.tip_difficulty(), block.header.difficulty);
        assert!(!blockchain.insert_with_check(&block));

        let mut blockchain = Blockchain::new();
        let key = key_pair::random();
        let signed_coinbase_tran = generate_signed_coinbase_transaction(&key);
        let content = Content::new_with_trans(&vec![signed_coinbase_tran.clone()]);
        let header = generate_header(&genesis_hash, &content, 0, &generate_random_hash());
        let block = Block::new(header, content);
        assert!(blockchain.insert(&block));

        let invalid_signed_tran = generate_random_signed_transaction();
        let content = Content::new_with_trans(&vec![invalid_signed_tran.clone()]);
        let header = generate_header(&block.hash, &content, 0, &generate_random_hash());
        let block = Block::new(header, content);
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
        blockchain.set_check_trans(false);
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
        blockchain.set_check_trans(false);
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
        blockchain.set_check_trans(false);
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
        blockchain.set_check_trans(false);
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
        blockchain.set_check_trans(false);
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
        blockchain.set_check_trans(false);
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
    fn test_get_block() {
        let mut blockchain = Blockchain::new();
        blockchain.set_check_trans(false);
        let genesis_hash = blockchain.tip();
        let block1 = generate_random_block(&genesis_hash);
        let block2 = generate_random_block(&block1.hash);
        let block3 = generate_random_block(&block2.hash);
        blockchain.insert(&block3);
        assert_eq!(block3, blockchain.get_block(&block3.hash).unwrap());
        assert_eq!(None, blockchain.get_block(&block1.hash));
        blockchain.insert(&block2);
        assert_eq!(block2, blockchain.get_block(&block2.hash).unwrap());
    }

    #[test]
    fn test_get_hash_chain() {
        let mut blockchain = Blockchain::new();
        blockchain.set_check_trans(false);
        let genesis_hash = blockchain.tip();
        let block1 = generate_random_block(&genesis_hash);
        let block2 = generate_random_block(&block1.hash);
        let block3 = generate_random_block(&block2.hash);
        blockchain.insert(&block1);
        blockchain.insert(&block2);
        blockchain.insert(&block3);
        let hashes = blockchain.hash_chain();
        assert_eq!(genesis_hash, hashes[3]);
        assert_eq!(block1.hash, hashes[2]);
        assert_eq!(block2.hash, hashes[1]);
        assert_eq!(block3.hash, hashes[0]);
    }

    #[test]
    fn test_get_header_chain() {
        let mut blockchain = Blockchain::new();
        blockchain.set_check_trans(false);
        let genesis_hash = blockchain.tip();
        let block1 = generate_random_block(&genesis_hash);
        let block2 = generate_random_block(&block1.hash);
        let block3 = generate_random_block(&block2.hash);
        blockchain.insert(&block1);
        blockchain.insert(&block2);
        blockchain.insert(&block3);
        let headers = blockchain.header_chain();
        assert_eq!(genesis_hash, headers[2].parent);
        assert_eq!(block1.hash, headers[1].parent);
        assert_eq!(block2.hash, headers[0].parent);
    }

    #[test]
    fn test_get_block_chain() {
        let mut blockchain = Blockchain::new();
        blockchain.set_check_trans(false);
        let genesis_hash = blockchain.tip();
        let block1 = generate_random_block(&genesis_hash);
        let block2 = generate_random_block(&block1.hash);
        let block3 = generate_random_block(&block2.hash);
        blockchain.insert(&block1);
        blockchain.insert(&block2);
        blockchain.insert(&block3);
        let blocks = blockchain.block_chain();
        assert_eq!(block1.hash, blocks[2].hash);
        assert_eq!(block2.hash, blocks[1].hash);
        assert_eq!(block3.hash, blocks[0].hash);
    }

    #[test]
    fn test_orphan() {
        let mut blockchain = Blockchain::new();
        blockchain.set_check_trans(false);
        let genesis_hash = blockchain.tip();
        let block1 = generate_random_block(&genesis_hash);
        let block2 = generate_random_block(&block1.hash);
        let block3 = generate_random_block(&block2.hash);
        assert!(!blockchain.is_orphan(&block3.hash));
        assert!(!blockchain.is_orphan(&block1.hash));
        blockchain.insert(&block2);
        blockchain.insert(&block3);
        assert!(blockchain.is_orphan(&block2.hash));
        assert!(blockchain.is_orphan(&block3.hash));
        assert!(!blockchain.is_orphan(&block1.hash));
        assert_eq!(block1.hash, blockchain.missing_parent(&block3.hash).unwrap());
        assert_eq!(block1.hash, blockchain.missing_parent(&block2.hash).unwrap());
        blockchain.insert(&block1);
        assert!(!blockchain.is_orphan(&block3.hash));
        assert!(!blockchain.is_orphan(&block2.hash));
        assert!(!blockchain.is_orphan(&block1.hash));
        assert_eq!(None, blockchain.missing_parent(&block3.hash));
        assert_eq!(None, blockchain.missing_parent(&block2.hash));
        assert_eq!(None, blockchain.missing_parent(&block1.hash));
    }

    #[test]
    fn test_sync_longest_chain() {
        let p2p_addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17051);
        let p2p_addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17052);

        let (server_1, _, _, blockchain_1, _, _, account_1) = new_server_env(p2p_addr_1);
        let (server_2, _, _, blockchain_2, _, _, account_2) = new_server_env(p2p_addr_2);

        // server_1 online but no connections
        let addr_1 = account_1.addr;
        let addr_2 = account_2.addr;
        server_1.broadcast(Message::Introduce(addr_1));
        thread::sleep(time::Duration::from_millis(100));
        blockchain_1.lock().unwrap().set_check_trans(false);
        blockchain_2.lock().unwrap().set_check_trans(false);

        let mut chain_1 = blockchain_1.lock().unwrap();
        let mut chain_2 = blockchain_2.lock().unwrap();

        let genesis = chain_1.tip();
        let difficulty = chain_1.difficulty();
        let block_1 = generate_mined_block(&genesis, &difficulty);
        chain_1.insert(&block_1);
        let block_2 = generate_mined_block(&block_1.hash, &difficulty);
        chain_1.insert(&block_2);
        drop(chain_1);
        drop(chain_2);

        // server_2 online & connect to server_1
        let server_peers_1 = vec![p2p_addr_1];
        connect_peers(&server_2, server_peers_1.clone());
        thread::sleep(time::Duration::from_millis(100));

        server_2.broadcast(Message::Introduce(addr_2));
        thread::sleep(time::Duration::from_millis(100));

        // Check if blockchain is sync
        chain_1 = blockchain_1.lock().unwrap();
        chain_2 = blockchain_2.lock().unwrap();
        assert_eq!(chain_1.length(), chain_2.length());
        assert!(chain_2.exist(&block_1.hash));
        assert!(chain_2.exist(&block_2.hash));
    }

    #[test]
    fn midtermproject1_insert_one() {
        let mut blockchain = Blockchain::new();
        blockchain.set_check_trans(false);
        let genesis_hash = blockchain.tip();
        let block = generate_random_block(&genesis_hash);
        blockchain.insert(&block);
        assert_eq!(blockchain.tip(), block.hash());
    }
    #[test]
    fn midtermproject1_insert_3_2() {
        let mut blockchain = Blockchain::new();
        blockchain.set_check_trans(false);
        let genesis_hash = blockchain.tip();
        let block_1 = generate_random_block(&genesis_hash);
        blockchain.insert(&block_1);
        assert_eq!(blockchain.tip(), block_1.hash());
        let block_2 = generate_random_block(&block_1.hash());
        blockchain.insert(&block_2);
        assert_eq!(blockchain.tip(), block_2.hash());
        let block_3 = generate_random_block(&block_2.hash());
        blockchain.insert(&block_3);
        assert_eq!(blockchain.tip(), block_3.hash());
        let fork_block_1 = generate_random_block(&genesis_hash);
        blockchain.insert(&fork_block_1);
        assert_eq!(blockchain.tip(), block_3.hash());
        let fork_block_2 = generate_random_block(&fork_block_1.hash());
        blockchain.insert(&fork_block_2);
        assert_eq!(blockchain.tip(), block_3.hash());
    }
    #[test]
    fn midtermproject1_insert_2_3() {
        let mut blockchain = Blockchain::new();
        blockchain.set_check_trans(false);
        let genesis_hash = blockchain.tip();
        let block_1 = generate_random_block(&genesis_hash);
        blockchain.insert(&block_1);
        assert_eq!(blockchain.tip(), block_1.hash());
        let block_2 = generate_random_block(&block_1.hash());
        blockchain.insert(&block_2);
        assert_eq!(blockchain.tip(), block_2.hash());
        let fork_block_1 = generate_random_block(&genesis_hash);
        blockchain.insert(&fork_block_1);
        assert_eq!(blockchain.tip(), block_2.hash());
        let fork_block_2 = generate_random_block(&fork_block_1.hash());
        blockchain.insert(&fork_block_2);
        //assert_eq!(blockchain.tip(), block_2.hash());
        let fork_block_3 = generate_random_block(&fork_block_2.hash());
        blockchain.insert(&fork_block_3);
        assert_eq!(blockchain.tip(), fork_block_3.hash());
    }
    #[test]
    fn midtermproject1_insert_3_fork_and_back() {
        let mut blockchain = Blockchain::new();
        blockchain.set_check_trans(false);
        let genesis_hash = blockchain.tip();
        let block_1 = generate_random_block(&genesis_hash);
        blockchain.insert(&block_1);
        assert_eq!(blockchain.tip(), block_1.hash());
        let block_2 = generate_random_block(&block_1.hash());
        blockchain.insert(&block_2);
        assert_eq!(blockchain.tip(), block_2.hash());
        let block_3 = generate_random_block(&block_2.hash());
        blockchain.insert(&block_3);
        assert_eq!(blockchain.tip(), block_3.hash());
        let fork_block_1 = generate_random_block(&block_2.hash());
        blockchain.insert(&fork_block_1);
        let fork_block_2 = generate_random_block(&fork_block_1.hash());
        blockchain.insert(&fork_block_2);
        assert_eq!(blockchain.tip(), fork_block_2.hash());
        let block_4 = generate_random_block(&block_3.hash());
        blockchain.insert(&block_4);
        let block_5 = generate_random_block(&block_4.hash());
        blockchain.insert(&block_5);
        assert_eq!(blockchain.tip(), block_5.hash());
    }
    #[test]
    fn midtermproject1_insert_3_fork_and_6() {
        let mut blockchain = Blockchain::new();
        blockchain.set_check_trans(false);
        let genesis_hash = blockchain.tip();
        let block_1 = generate_random_block(&genesis_hash);
        blockchain.insert(&block_1);
        assert_eq!(blockchain.tip(), block_1.hash());
        let block_2 = generate_random_block(&block_1.hash());
        blockchain.insert(&block_2);
        assert_eq!(blockchain.tip(), block_2.hash());
        let block_3 = generate_random_block(&block_2.hash());
        blockchain.insert(&block_3);
        assert_eq!(blockchain.tip(), block_3.hash());
        let fork_block_1 = generate_random_block(&block_2.hash());
        blockchain.insert(&fork_block_1);
        let fork_block_2 = generate_random_block(&fork_block_1.hash());
        blockchain.insert(&fork_block_2);
        assert_eq!(blockchain.tip(), fork_block_2.hash());
        let another_block_1 = generate_random_block(&genesis_hash);
        blockchain.insert(&another_block_1);
        assert_eq!(blockchain.tip(), fork_block_2.hash());
        let another_block_2 = generate_random_block(&another_block_1.hash());
        blockchain.insert(&another_block_2);
        assert_eq!(blockchain.tip(), fork_block_2.hash());
        let another_block_3 = generate_random_block(&another_block_2.hash());
        blockchain.insert(&another_block_3);
        assert_eq!(blockchain.tip(), fork_block_2.hash());
        let another_block_4 = generate_random_block(&another_block_3.hash());
        blockchain.insert(&another_block_4);
        let another_block_5 = generate_random_block(&another_block_4.hash());
        blockchain.insert(&another_block_5);
        assert_eq!(blockchain.tip(), another_block_5.hash());
        let another_block_6 = generate_random_block(&another_block_5.hash());
        blockchain.insert(&another_block_6);
        assert_eq!(blockchain.tip(), another_block_6.hash());
    }

    #[test]
    fn test_validate_block_meta() {
        let mut blockchain = Blockchain::new();
        let genesis_hash = blockchain.tip();
        let difficulty: H256 = gen_difficulty_array(0).into();
        blockchain.change_difficulty(&difficulty);
        let mut block = generate_block(&genesis_hash, 40, &difficulty);
        assert!(blockchain.validate_block_meta(&block));

        // Hash Validate
        let hash: H256 = gen_difficulty_array(20).into();
        block.change_hash(&hash);
        assert!(!blockchain.validate_block_meta(&block));

        //POW validate
        let difficulty: H256 = gen_difficulty_array(20).into();
        blockchain.change_difficulty(&difficulty);
        let block = generate_block(&genesis_hash, 1, &difficulty);
        assert!(!blockchain.validate_block_meta(&block));
    }
}
