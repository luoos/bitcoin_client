use std::sync::{Arc, Mutex};
use std::thread;
use std::time;
use log::info;

use crate::network::server::Handle as ServerHandle;
use crate::network::message::Message;
use crate::mempool::MemPool;
use crate::helper::{generate_signed_transaction, generate_random_signed_transaction_from_keypair};
use crate::crypto::hash::{Hashable, H160, H256};
use crate::config::{TRANSACTION_GENERATE_INTERVAL, VALID_OUTPUTS_NUM};
use crate::block::State;
use crate::peers::Peers;
use std::collections::{HashMap, HashSet};
use rand::Rng;
use crate::transaction::{TxOutput, TxInput};
use crate::blockchain::Blockchain;
use crate::account::Account;
use std::cmp::min;

pub struct Context {
    server: ServerHandle,
    mempool: Arc<Mutex<MemPool>>,
    blockchain: Arc<Mutex<Blockchain>>,
    state: State,
    peers: Arc<Mutex<Peers>>,
    account: Arc<Account>,
}

pub fn new(
    server: &ServerHandle,
    mempool: &Arc<Mutex<MemPool>>,
    blockchain: &Arc<Mutex<Blockchain>>,
    state: &State,
    peers: &Arc<Mutex<Peers>>,
    account: &Arc<Account>,
) -> Context {
    Context {
        server: server.clone(),
        mempool: Arc::clone(mempool),
        blockchain: Arc::clone(blockchain),
        state: state.clone(),
        peers: Arc::clone(peers),
        account: Arc::clone(account),
    }
}

impl Context {
    pub fn start(mut self) {
        thread::Builder::new()
            .name("transaction_generator".to_string())
            .spawn(move|| {
                self.transaction_generator_loop();
            })
            .unwrap();
        info!("Transaction generator Started");
    }

    pub fn transaction_generator_loop(&mut self) {
        loop {
            // Update state from tip of longest-chain
            let blockchain = self.blockchain.lock().unwrap();
            if blockchain.length() > 1 {
                self.state = blockchain.tip_block_state();
            }
            drop(blockchain);

            self.generating();

            let sleep_itv = time::Duration::from_millis(TRANSACTION_GENERATE_INTERVAL);
            thread::sleep(sleep_itv);
        }
    }

    //For now, just call generate_random_signed_transaction
    pub fn generating(&mut self) {
        let new_t = generate_random_signed_transaction_from_keypair(&self.account.key_pair);
        let mut mempool = self.mempool.lock().unwrap();
        if mempool.add_with_check(&new_t) {
            info!("Generate new transaction with {} input {} output! Now mempool has {} transaction",
                new_t.transaction.inputs.len(), new_t.transaction.outputs.len(), mempool.size());
            let vec = vec![new_t.hash().clone()];
            self.server.broadcast(Message::NewTransactionHashes(vec));
        }
        drop(mempool);
    }

    //Create valid transactions under current state
    pub fn generating_valid_trans(&mut self) {
        let cur_state = self.state.0.clone();
        if cur_state.is_empty() {
            return;
        }

        // create (value, receiver address) pair for this transaction
        let pick_outputs = self.pick_unspent_output();
        let pick_addrs = self.pick_peer_addrs();

        // Check prerequisite to generate a new transaction
        if let Some((input, output)) = pick_outputs {
            if let Some(peer_addrs) = pick_addrs {
                let send_val = self.pick_send_value(output.val);

                assert_eq!(send_val.len(), peer_addrs.len() + 1);
                let peer_num = peer_addrs.len();

                let tx_inputs: Vec<TxInput> = vec![input];
                let mut tx_outputs = Vec::<TxOutput>::new();

                for idx in 0..peer_num {
                    tx_outputs.push(TxOutput::new(peer_addrs[idx], send_val[idx]));
                }
                tx_outputs.push(TxOutput::new(self.account.addr, send_val[peer_num + 1]));

                let new_t = generate_signed_transaction(&self.account.key_pair, tx_inputs, tx_outputs);
                let mut mempool = self.mempool.lock().unwrap();
                if mempool.add_with_check(&new_t) {
                    info!("Generate new transaction with {} input {} output! Now mempool has {} transaction",
                          new_t.transaction.inputs.len(), new_t.transaction.outputs.len(), mempool.size());
                    let vec = vec![new_t.hash().clone()];
                    self.server.broadcast(Message::NewTransactionHashes(vec));
                }
                drop(mempool);
            }
        }
    }

    // Pick a (TxInput, TxOutput) pair from unspent outputs sent to user
    fn pick_unspent_output(&self) -> Option<(TxInput, TxOutput)> {
        let cur_state: HashMap<(H256, u32), (u64, H160)> = self.state.0.clone();

        let mut self_output = Vec::<(TxInput, TxOutput)>::new();

        for (input, output) in cur_state.iter() {
            if output.1 == self.account.addr {
                self_output.push((
                    TxInput::new(input.0, input.1), TxOutput::new(output.1, output.0)));
            }
        }

        if self_output.len() > 0 {
            let mut rng = rand::thread_rng();
            let idx = rng.gen_range(0, self_output.len());
            return self_output.get(idx).cloned();
        }
        None
    }

    // Pick random peers to as receiver of new transaction
    fn pick_peer_addrs(&self) -> Option<Vec<H160>> {
        let mut peer_addrs = Vec::new();

        let peers = self.peers.lock().unwrap();
        let all_peer_addrs = peers.addrs.clone();
        drop(peers);

        let peer_num = all_peer_addrs.len();
        let pick_num = min(VALID_OUTPUTS_NUM - 1, peer_num);

        let mut rng = rand::thread_rng();
        let mut candidates: HashSet<usize> = HashSet::new();
        while candidates.len() < pick_num {
            let num = rng.gen_range(0, peer_num);
            if let None = candidates.get(&num) {
                candidates.insert(num);
            }
        }

        let mut cnt: usize = 0;
        if pick_num == 0 {
            return None;
        } else {
            // Arbitrary order traversal
            for addr in all_peer_addrs.iter() {
                if let Some(_) = candidates.get(&cnt) {
                    peer_addrs.push(addr.clone());
                }
                cnt += 1;
            }
        }

        if peer_addrs.len() > 0 {
            return Some(peer_addrs);
        }
        None
    }

    // Pick random value to specific peer
    fn pick_send_value(&self, mut total_val: u64) -> Vec<u64> {
        let peers = self.peers.lock().unwrap();
        let peer_num = peers.addrs.len();
        drop(peers);

        let mut output_values = Vec::new();
        let mut rng = rand::thread_rng();

        //Last portion for myself
        let portions = min(VALID_OUTPUTS_NUM, peer_num + 1);
        let mut val: u64;

        for idx in 0..portions {
            if idx != portions - 1 {
                val = rng.gen_range(1, total_val);
            } else {
                val = total_val;
            }
            output_values.push(val);
            total_val -= val;
        }
        println!("{:?}", output_values);
        output_values
    }

    // Get user's balance under current state
    #[allow(dead_code)]
    fn get_cur_balance(&self) -> u64 {
        let mut self_balance: u64 = 0;

        let cur_state: HashMap<(H256, u32), (u64, H160)> = self.state.0.clone();

        for (_, (val, rec_addr)) in cur_state.iter() {
            if rec_addr.clone() == self.account.addr {
                self_balance += val.clone();
            }
        }
        self_balance
    }
}

#[cfg(any(test, test_utilities))]
mod tests {
    use std::net::{SocketAddr, IpAddr, Ipv4Addr};
    use std::thread::sleep;
    use std::time;
    use std::collections::HashSet;

    use crate::helper::*;
    use crate::config::{COINBASE_REWARD, REPEAT_TEST_TIME, VALID_OUTPUTS_NUM};
    use crate::transaction::{TxInput, TxOutput};
    use crate::crypto::hash::H160;

    #[test]
    fn test_transaction_relay() {
        let p2p_addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17021);
        let p2p_addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17022);
        let p2p_addr_3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17023);

        let (_server_1, _miner_ctx_1, mut generator_1,  _blockchain_1, mempool_1, _, _) = new_server_env(p2p_addr_1);
        let (server_2, _miner_ctx_2, mut generator_2, _blockchain_2, mempool_2, _, _) = new_server_env(p2p_addr_2);
        let (server_3, _miner_ctx_3, mut generator_3, _blockchain_3, mempool_3, _, _) = new_server_env(p2p_addr_3);

        let peers_1 = vec![p2p_addr_1];
        connect_peers(&server_2, peers_1);
        let peers_2 = vec![p2p_addr_2];
        connect_peers(&server_3, peers_2);

        generator_1.generating();
        sleep(time::Duration::from_millis(100));

        let pool_1 = mempool_1.lock().unwrap();
        let pool_2 = mempool_2.lock().unwrap();
        let pool_3 = mempool_3.lock().unwrap();
        assert_eq!(pool_1.size(), 1);
        assert_eq!(pool_1.size(), pool_2.size());
        assert_eq!(pool_1.size(), pool_3.size());
        drop(pool_1);
        drop(pool_2);
        drop(pool_3);

        generator_2.generating();
        sleep(time::Duration::from_millis(100));

        let pool_1 = mempool_1.lock().unwrap();
        let pool_2 = mempool_2.lock().unwrap();
        let pool_3 = mempool_3.lock().unwrap();
        assert_eq!(pool_1.size(), 2);
        assert_eq!(pool_1.size(), pool_2.size());
        assert_eq!(pool_1.size(), pool_3.size());
        drop(pool_1);
        drop(pool_2);
        drop(pool_3);

        generator_3.generating();
        sleep(time::Duration::from_millis(100));

        let pool_1 = mempool_1.lock().unwrap();
        let pool_2 = mempool_2.lock().unwrap();
        let pool_3 = mempool_3.lock().unwrap();
        assert_eq!(pool_1.size(), 3);
        assert_eq!(pool_1.size(), pool_2.size());
        assert_eq!(pool_1.size(), pool_3.size());
        drop(pool_1);
        drop(pool_2);
        drop(pool_3);
    }

    #[test]
    fn test_pick_unspent_output() {
        let p2p_addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17027);
        let (_, _, mut generator,  _, _, _, account) = new_server_env(p2p_addr_1);

        let peer_addr1 = generate_random_h160();
        let peer_addr2 = generate_random_h160();
        let key = &account.key_pair;
        let self_addr = account.addr;
        //Empty state
        assert!(generator.pick_unspent_output().is_none());

        //Create & insert state manually (me: 0)
        // -> 0: COIN_BASE
        let coinbase_trans_hash = generate_signed_coinbase_transaction(key).hash;
        generator.state.insert((coinbase_trans_hash, 0), (COINBASE_REWARD, self_addr));
        assert!(generator.pick_unspent_output().is_some());
        assert_eq!(generator.pick_unspent_output().unwrap(), (TxInput::new(coinbase_trans_hash, 0), TxOutput::new(self_addr, COINBASE_REWARD)));
        generator.state.clear();
        assert!(generator.pick_unspent_output().is_none());

        // 1 -> 0: COIN_BASE / 2, 1 -> 2: COIN_BASE / 2
        let rand_trans_hash_1 = generate_random_hash();
        generator.state.insert((rand_trans_hash_1, 0), (COINBASE_REWARD/2, self_addr));
        generator.state.insert((rand_trans_hash_1, 1), (COINBASE_REWARD/2, peer_addr2));
        assert!(generator.pick_unspent_output().is_some());

        for _ in 0..REPEAT_TEST_TIME {
            let result = generator.pick_unspent_output().unwrap();
            assert!(result.1.rec_address == self_addr && result.0.pre_hash == rand_trans_hash_1 && result.1.val == COINBASE_REWARD/2);
        }

        // 2 -> 0: COIN_BASE / 2, 2 -> 1: COIN_BASE / 2
        let rand_trans_hash_2 = generate_random_hash();
        generator.state.insert((rand_trans_hash_2, 0), (COINBASE_REWARD/2, self_addr));
        generator.state.insert((rand_trans_hash_2, 1), (COINBASE_REWARD/2, peer_addr1));

        let mut cnt_1 = 0;
        let mut cnt_2 = 0;
        for _ in 0..REPEAT_TEST_TIME {
            let result = generator.pick_unspent_output().unwrap();
            assert!(result.1.rec_address == self_addr && result.0.index == 0);
            let trans_idx = result.0.pre_hash;
            if trans_idx == rand_trans_hash_1 {
                cnt_1 += 1;
            } else if trans_idx == rand_trans_hash_2 {
                cnt_2 += 1;
            } else {
                assert!(false);
            }
            assert!(cnt_1 != REPEAT_TEST_TIME && cnt_2 != REPEAT_TEST_TIME);
        }
    }

    #[test]
    fn test_pick_peer_addrs() {
        let p2p_addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17028);
        let (_, _, generator,  _, _, locked_peers, _) = new_server_env(p2p_addr_1);

        let peer_addr1 = generate_random_h160();
        let peer_addr2 = generate_random_h160();
        let peer_addr3 = generate_random_h160();

        let mut peers = locked_peers.lock().unwrap();
        peers.insert(&peer_addr1);
        drop(peers);

        assert!(generator.pick_peer_addrs().is_some());
        let mut addrs = generator.pick_peer_addrs().unwrap();
        assert!(addrs == vec![peer_addr1]);

        peers = locked_peers.lock().unwrap();
        peers.insert(&peer_addr2);
        peers.insert(&peer_addr3);
        drop(peers);

        let mut all_addrs_combination: HashSet<Vec<H160>> = HashSet::new();

        // When config = 3 (May need to change later)
        all_addrs_combination.insert(vec![peer_addr1, peer_addr2]);
        all_addrs_combination.insert(vec![peer_addr1, peer_addr3]);
        all_addrs_combination.insert(vec![peer_addr2, peer_addr1]);
        all_addrs_combination.insert(vec![peer_addr2, peer_addr3]);
        all_addrs_combination.insert(vec![peer_addr3, peer_addr1]);
        all_addrs_combination.insert(vec![peer_addr3, peer_addr2]);

        for _ in 0..REPEAT_TEST_TIME {
            addrs = generator.pick_peer_addrs().unwrap();
            assert!(all_addrs_combination.get(&addrs).is_some());
        }
    }

    #[test]
    fn test_pick_send_value() {
        let p2p_addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17027);
        let (_, _, generator,  _, _, locked_peers, _) = new_server_env(p2p_addr_1);

        let peer_addr1 = generate_random_h160();
        let peer_addr2 = generate_random_h160();
        let peer_addr3 = generate_random_h160();

        let mut peers = locked_peers.lock().unwrap();
        peers.insert(&peer_addr1);
        let mut peer_num = peers.addrs.len();
        drop(peers);

        let total_1 = COINBASE_REWARD;
        let res_1 =generator.pick_send_value(total_1);
        assert_eq!(peer_num, 1);
        assert_eq!(res_1.len(), peer_num + 1);
        let sum_1: u64 = res_1.iter().sum();
        assert_eq!(sum_1, COINBASE_REWARD);
        assert_ne!(res_1[0], res_1[1]);

        let mut peers = locked_peers.lock().unwrap();
        peers.insert(&peer_addr2);
        peers.insert(&peer_addr3);
        peer_num = peers.addrs.len();
        drop(peers);

        //Set a large number to avoid duplicate
        let total_2 = 10 * COINBASE_REWARD;
        for _ in 0..REPEAT_TEST_TIME {
            let res_2 =generator.pick_send_value(total_2);
            assert_eq!(peer_num, 3);
            assert_eq!(res_2.len(), VALID_OUTPUTS_NUM);
            let sum_2: u64 = res_2.iter().sum();
            assert_eq!(sum_2, 10 * COINBASE_REWARD);
            // Test randomness
            let mut val_set: HashSet<u64> = HashSet::new();
            for val in res_2.iter() {
                if let Some(_) = val_set.get(val) {
                    assert!(false);
                }
                val_set.insert(val.clone());
            }
        }

    }
}