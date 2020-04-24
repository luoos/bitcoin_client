use crate::crypto::hash::H256;
use crate::transaction::{SignedTransaction, TxInput};
use crate::block::Content;
use crate::config::POOL_SIZE_LIMIT;
use crate::helper;

use std::collections::HashMap;
use log::debug;
use ring::signature::Ed25519KeyPair;
use crate::helper::generate_signed_coinbase_transaction;

pub struct MemPool {
    pub transactions: HashMap<H256, SignedTransaction>,
    pub input_tran_map: HashMap<TxInput, (H256, u64)>, //Key: TxInput, Val: (hash, timestamp)
    timestamp_map: HashMap<H256, i64>,
}

impl MemPool {
    // Create an empty mempool
    pub fn new() -> Self {
        let transactions: HashMap<H256, SignedTransaction> = HashMap::new();
        let input_tran_map: HashMap<TxInput, (H256, u64)> = HashMap::<TxInput, (H256, u64)>::new();
        Self {
            transactions,
            input_tran_map,
            timestamp_map: HashMap::new(),
        }
    }

    // Randomly create and init with n trans
    pub fn new_with_trans(trans: &Vec<SignedTransaction>) -> Self {
        let mut mempool = Self::new();
        for t in trans.iter() {
            mempool.add_with_check(t);
        }
        return mempool;
    }

    // Add a valid transaction after signature check && double-spend txinput check
    pub fn add_with_check(&mut self, tran: &SignedTransaction) -> bool {
        if self.exist(&tran.hash) || !tran.sign_check() || self.size() >= POOL_SIZE_LIMIT {
            return false;
        }
        return self.try_insert(tran);
    }

    // try insert transaction if no conflict input
    // or the transaction has the minimal timestamp among conflict trans
    fn try_insert(&mut self, tran: &SignedTransaction) -> bool {
        debug!("Try to add {:?} into mempool", tran);
        let mut to_remove_hash: Vec<H256> = Vec::new();
        let ts = tran.transaction.ts;
        for input in tran.transaction.inputs.iter() {
            if let Some((conf_hash, conf_ts)) = self.input_tran_map.get(input) {
                if ts < *conf_ts {
                    to_remove_hash.push(conf_hash.clone());
                } else {
                    return false; // conflict and has bigger timestamp
                }
            }
        }
        // remove conflict trans
        for conf_hash in to_remove_hash.iter() {
            self.transactions.remove(conf_hash);
            self.timestamp_map.remove(conf_hash);
        }

        for input in tran.transaction.inputs.iter() {
            self.input_tran_map.insert(input.clone(), (tran.hash, ts));
        }
        self.transactions.insert(tran.hash.clone(), tran.clone());
        self.timestamp_map.insert(tran.hash.clone(), helper::get_current_time_in_nano());
        return true;
    }

    // Remove transactions from pool
    pub fn remove_trans(&mut self, trans: &Vec<H256>) {
        for hash in trans.iter() {
            if let Some(_) = self.transactions.get(&hash) {
                self.transactions.remove(&hash);
                self.timestamp_map.remove(&hash);
            } else {
                debug!("{:?} not exist in the mempool!", hash);
            }
        }
        if self.empty() {
            debug!("Mempool is empty!");
        }
    }

    // Remove inputs conflict with already-inserted-to-blockchain ones
    pub fn remove_conflict_tx_inputs(&mut self, content: &Content) {
        for trans in content.trans.iter() {
            let inputs = &trans.transaction.inputs;
            for input in inputs.iter() {
                if let Some((tx_hash,_)) = self.input_tran_map.remove(input) {
                    debug!("Remove conflicting input from mempool {:?}", input);
                    self.transactions.remove(&tx_hash);
                    self.timestamp_map.remove(&tx_hash);
                }
            }
        }
    }

    // Create content for miner's block to include as many transactions as possible
    pub fn create_content(&self, key_pair: &Ed25519KeyPair) -> Content {
        let mut trans = Vec::<SignedTransaction>::new();

        let coinbase_trans = generate_signed_coinbase_transaction(key_pair);
        trans.push(coinbase_trans);

        for (_, tran) in self.transactions.iter() {
            trans.push(tran.clone());
        }
        Content::new_with_trans(&trans)
    }

    // check existence of a hash
    pub fn exist(&self, hash: &H256) -> bool {
        self.transactions.contains_key(hash)
    }

    // Given hashes, get transactions from mempool
    pub fn get_trans(&self, hashes: &Vec<H256>) -> Vec<SignedTransaction> {
        let mut trans = Vec::<SignedTransaction>::new();
        for h in hashes.iter() {
            if let Some(t) = self.transactions.get(h) {
                trans.push(t.clone());
            }
        }
        trans
    }

    // Number of available transactions
    pub fn size(&self) -> usize {
        self.transactions.len()
    }

    // Check if no transaction in pool
    pub fn empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

#[cfg(any(test, test_utilities))]
mod tests {
    use super::*;
    use crate::helper::*;
    use crate::block::{Block, Content};
    use crate::network::message::Message;
    use crate::spread::Spreader;
    use crate::config::EASIEST_DIF;
    use crate::crypto::{key_pair, hash::Hashable};
    use std::net::{SocketAddr, IpAddr, Ipv4Addr};
    use std::thread::sleep;
    use std::time;

    #[test]
    fn test_add_with_check() {
        let mut mempool = MemPool::new();
        assert!(mempool.empty());
        let t = generate_random_signed_transaction();
        let t_2 = generate_random_signed_transaction();
        assert!(mempool.add_with_check(&t));
        assert_eq!(mempool.size(), 1);
        assert!(mempool.exist(&t.hash()));
        assert!(!mempool.exist(&t_2.hash()));
        assert!(!mempool.add_with_check(&t));
        assert!(mempool.add_with_check(&t_2));
        assert_eq!(mempool.size(), 2);
        assert_eq!(mempool.get_trans(&vec![t.hash(), t_2.hash()]).len(), 2);
    }

    #[test]
    fn test_remove_trans() {
        let mut mempool = MemPool::new();
        let t = generate_random_signed_transaction();
        let t_2 = generate_random_signed_transaction();
        let t_3 = generate_random_signed_transaction();

        mempool.add_with_check(&t);
        mempool.remove_trans(&vec![t.hash(), t_2.hash()]);
        assert!(mempool.empty());

        mempool.add_with_check(&t_2);
        mempool.add_with_check(&t_3);
        assert_eq!(mempool.size(), 2);
        assert!(!mempool.exist(&t.hash()));
        mempool.remove_trans(&vec![t.hash(), t_2.hash()]);
        assert_eq!(mempool.size(), 1);
        assert!(mempool.exist(&t_3.hash()));
    }

    #[test]
    fn test_create_trans() {
        let key = key_pair::random();
        let mut mempool = MemPool::new();
        let mut t = generate_random_signed_transaction();
        mempool.add_with_check(&t);
        t = generate_random_signed_transaction();
        mempool.add_with_check(&t);
        t = generate_random_signed_transaction();
        mempool.add_with_check(&t);

        let content = mempool.create_content(&key);
        assert_eq!(content.trans.len(), 4);
    }

    #[test]
    fn test_mempool_clear() {
        let p2p_addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17031);
        let p2p_addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17032);
        let p2p_addr_3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17033);

        let (_server_1, _miner_ctx_1, mut _generator_1,  _blockchain_1, mempool_1, _, _) = new_server_env(p2p_addr_1, Spreader::Default, false);
        let (server_2, _miner_ctx_2, mut _generator_2, _blockchain_2, mempool_2, _, _) = new_server_env(p2p_addr_2, Spreader::Default, false);
        let (server_3, _miner_ctx_3, mut _generator_3, blockchain_3, _mempool_3, _, _) = new_server_env(p2p_addr_3, Spreader::Default, false);
        _blockchain_1.lock().unwrap().set_check_trans(false);
        _blockchain_2.lock().unwrap().set_check_trans(false);
        blockchain_3.lock().unwrap().set_check_trans(false);

        let peers_1 = vec![p2p_addr_1];
        connect_peers(&server_2, &peers_1);
        let peers_2 = vec![p2p_addr_2];
        connect_peers(&server_3, &peers_2);

        let t_1 = generate_random_signed_transaction();
        let t_2 = generate_random_signed_transaction();
        let t_3 = generate_random_signed_transaction();

        let mut pool_1 = mempool_1.lock().unwrap();
        pool_1.add_with_check(&t_1);
        pool_1.add_with_check(&t_2);
        pool_1.add_with_check(&t_3);
        drop(pool_1);

        let mut pool_2 = mempool_2.lock().unwrap();
        pool_2.add_with_check(&t_1);
        pool_2.add_with_check(&t_2);
        pool_2.add_with_check(&t_3);
        drop(pool_2);

        let mut chain_3 = blockchain_3.lock().unwrap();
        let difficulty: H256 = gen_difficulty_array(EASIEST_DIF).into();
        let content = Content::new_with_trans(&vec![t_1, t_2, t_3]);
        let header = generate_header(&chain_3.tip(), &content, 0, &difficulty);
        let new_block = Block::new(header, content);
        chain_3.insert(&new_block);
        drop(chain_3);

        // Server3 Only broadcasts a new block
        server_3.broadcast(Message::NewBlockHashes(vec![new_block.hash()]));
        sleep(time::Duration::from_millis(100));
        // Check server1&2 remove all the transactions within this new block
        pool_1 = mempool_1.lock().unwrap();
        pool_2 = mempool_2.lock().unwrap();
        assert!(pool_2.empty());
        assert!(pool_1.empty());
        drop(pool_1);
        drop(pool_2);
    }

    #[test]
    fn test_try_insert() {
        let key = key_pair::random();
        let mut mempool = MemPool::new();
        let h256 = generate_random_hash();
        let input = TxInput {pre_hash: h256, index: 0};
        let signed_tran_1 = generate_signed_transaction(&key, vec![input.clone()], Vec::new());
        sleep(time::Duration::from_millis(10));
        let signed_tran_2 = generate_signed_transaction(&key, vec![input.clone()], Vec::new());
        assert!(mempool.try_insert(&signed_tran_2));
        assert!(mempool.exist(&signed_tran_2.hash));
        assert!(mempool.try_insert(&signed_tran_1));
        assert!(!mempool.try_insert(&signed_tran_2));
        assert!(mempool.exist(&signed_tran_1.hash));
        assert!(!mempool.exist(&signed_tran_2.hash));
    }

    #[test]
    fn test_remove_conflict_tx_inputs() {
        let key = key_pair::random();
        let mut mempool = MemPool::new();
        let h256 = generate_random_hash();
        let input = TxInput {pre_hash: h256, index: 0};
        let signed_tran_1 = generate_signed_transaction(&key, vec![input.clone()], Vec::new());
        sleep(time::Duration::from_millis(10));
        let signed_tran_2 = generate_signed_transaction(&key, vec![input.clone()], Vec::new());
        let content_2 = Content::new_with_trans(&vec![signed_tran_2.clone()]);
        assert!(mempool.try_insert(&signed_tran_1));
        assert!(mempool.exist(&signed_tran_1.hash));
        assert!(!mempool.exist(&signed_tran_2.hash));
        mempool.remove_conflict_tx_inputs(&content_2);
        assert!(!mempool.exist(&signed_tran_1.hash));
    }
}