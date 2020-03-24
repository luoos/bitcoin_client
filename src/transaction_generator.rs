use std::sync::{Arc, Mutex};
use std::thread;
use std::time;
use log::{info, debug};
use rand::Rng;
use std::cmp::min;

use crate::network::server::Handle as ServerHandle;
use crate::network::message::Message;
use crate::mempool::MemPool;
use crate::helper::{generate_signed_transaction, generate_random_signed_transaction_from_keypair};
use crate::crypto::hash::{Hashable, H160};
use crate::config::{TRANSACTION_GENERATE_INTERVAL};
use crate::block::State;
use crate::peers::Peers;
use crate::transaction::{TxOutput, TxInput};
use crate::blockchain::Blockchain;
use crate::account::Account;

pub struct Context {
    server: ServerHandle,
    mempool: Arc<Mutex<MemPool>>,
    blockchain: Arc<Mutex<Blockchain>>,
    peers: Arc<Mutex<Peers>>,
    account: Arc<Account>,
}

pub fn new(
    server: &ServerHandle,
    mempool: &Arc<Mutex<MemPool>>,
    blockchain: &Arc<Mutex<Blockchain>>,
    peers: &Arc<Mutex<Peers>>,
    account: &Arc<Account>,
) -> Context {
    Context {
        server: server.clone(),
        mempool: Arc::clone(mempool),
        blockchain: Arc::clone(blockchain),
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
            let state = self.blockchain.lock().unwrap().tip_block_state();
            self.generating_valid_trans(&state);
            let sleep_itv = time::Duration::from_millis(TRANSACTION_GENERATE_INTERVAL);
            thread::sleep(sleep_itv);
        }
    }

    //For now, just call generate_random_signed_transaction
    pub fn generating(&mut self) {
        let new_t = generate_random_signed_transaction_from_keypair(&self.account.key_pair);
        let mut mempool = self.mempool.lock().unwrap();
        if mempool.add_with_check(&new_t) {
            debug!("Generate new transaction with {} input {} output! Now mempool has {} transaction",
                new_t.transaction.inputs.len(), new_t.transaction.outputs.len(), mempool.size());
            let vec = vec![new_t.hash().clone()];
            self.server.broadcast(Message::NewTransactionHashes(vec));
        }
        drop(mempool);
    }

    //Create valid transactions under current state (For now: Send to one peer & myself)
    pub fn generating_valid_trans(&mut self, state: &State) {
        // create (value, receiver address) pair for this transaction
        let pick_outputs = self.pick_unspent_output(state);
        let pick_addrs = self.pick_peer_addr();
        debug!("Ready to generate trans for peers {:?} from output {:?}", pick_addrs, pick_outputs);

        // Check prerequisite to generate a new transaction
        if let Some((input, output)) = pick_outputs {
            if let Some(peer_addrs) = pick_addrs {
                let send_val = self.pick_send_value(output.val, 2);

                let tx_inputs: Vec<TxInput> = vec![input];
                let mut tx_outputs = Vec::<TxOutput>::new();

                tx_outputs.push(TxOutput::new(peer_addrs, send_val[0]));
                if send_val.len() > 1 {
                    tx_outputs.push(TxOutput::new(self.account.addr, send_val[1]));
                }

                let new_t = generate_signed_transaction(&self.account.key_pair, tx_inputs, tx_outputs);
                let mut mempool = self.mempool.lock().unwrap();
                if mempool.add_with_check(&new_t) {
                    info!("Generate a new transaction! Now mempool has {} transaction", mempool.size());
                    let vec = vec![new_t.hash().clone()];
                    self.server.broadcast(Message::NewTransactionHashes(vec));
                }
                drop(mempool);
            }
        }
    }

    // Pick a (TxInput, TxOutput) pair from unspent outputs sent to user
    fn pick_unspent_output(&self, state: &State) -> Option<(TxInput, TxOutput)> {
        let cur_state = state.as_ref();

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

    // Pick single random peer to as receiver of new transaction
    fn pick_peer_addr(&self) -> Option<H160> {
        let peers = self.peers.lock().unwrap();
        let peer_addrs = peers.addrs.clone();
        let peer_num = peer_addrs.len();

        let mut rng = rand::thread_rng();

        if peer_num == 0 {
            return None;
        } else {
            let mut num = rng.gen_range(0, peer_num);
            for addr in peers.addrs.iter() {
                if num == 0 {
                    return Some(addr.clone());
                }
                num -= 1;
            }
        }
        drop(peers);
        None
    }

    // Pick random value to specific peer
    fn pick_send_value(&self, mut total_val: u64, mut portion: usize) -> Vec<u64> {
        let mut output_values = Vec::new();
        let mut rng = rand::thread_rng();

        let mut val: u64;

        // Deal with total_val < portion
        portion = min(portion, total_val as usize);

        for idx in 0..portion {
            if idx != portion - 1 {
                val = rng.gen_range(1, total_val);
            } else {
                val = total_val;
            }
            output_values.push(val);
            total_val -= val;
        }
        output_values
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
    use crate::block::State;
    use std::cmp::min;

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
        let (_, _, generator,  _, _, _, account) = new_server_env(p2p_addr_1);

        let peer_addr1 = generate_random_h160();
        let peer_addr2 = generate_random_h160();
        let key = &account.key_pair;
        let self_addr = account.addr;
        //Empty state
        let mut state = State::new();
        assert!(generator.pick_unspent_output(&state).is_none());

        //Create & insert state manually (me: 0)
        // -> 0: COIN_BASE
        let coinbase_trans_hash = generate_signed_coinbase_transaction(key).hash;
        state.insert((coinbase_trans_hash, 0), (COINBASE_REWARD, self_addr));
        assert!(generator.pick_unspent_output(&state).is_some());
        assert_eq!(generator.pick_unspent_output(&state).unwrap(), (TxInput::new(coinbase_trans_hash, 0), TxOutput::new(self_addr, COINBASE_REWARD)));
        state.clear();
        assert!(generator.pick_unspent_output(&state).is_none());

        // 1 -> 0: COIN_BASE / 2, 1 -> 2: COIN_BASE / 2
        let rand_trans_hash_1 = generate_random_hash();
        state.insert((rand_trans_hash_1, 0), (COINBASE_REWARD/2, self_addr));
        state.insert((rand_trans_hash_1, 1), (COINBASE_REWARD/2, peer_addr2));
        assert!(generator.pick_unspent_output(&state).is_some());

        for _ in 0..REPEAT_TEST_TIME {
            let result = generator.pick_unspent_output(&state).unwrap();
            assert!(result.1.rec_address == self_addr && result.0.pre_hash == rand_trans_hash_1 && result.1.val == COINBASE_REWARD/2);
        }

        // 2 -> 0: COIN_BASE / 2, 2 -> 1: COIN_BASE / 2
        let rand_trans_hash_2 = generate_random_hash();
        state.insert((rand_trans_hash_2, 0), (COINBASE_REWARD/2, self_addr));
        state.insert((rand_trans_hash_2, 1), (COINBASE_REWARD/2, peer_addr1));

        let mut cnt_1 = 0;
        let mut cnt_2 = 0;
        for _ in 0..REPEAT_TEST_TIME {
            let result = generator.pick_unspent_output(&state).unwrap();
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
    fn test_pick_peer_addr() {
        let p2p_addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17028);
        let (_, _, generator,  _, _, locked_peers, _) = new_server_env(p2p_addr_1);

        let peer_addr1 = generate_random_h160();
        let peer_addr2 = generate_random_h160();
        let peer_addr3 = generate_random_h160();

        let mut peers = locked_peers.lock().unwrap();
        peers.insert(&peer_addr1);
        peers.insert(&peer_addr2);
        peers.insert(&peer_addr3);
        drop(peers);

        for _ in 0..REPEAT_TEST_TIME {
            assert!(generator.pick_peer_addr().is_some());
            let addr = generator.pick_peer_addr().unwrap();
            assert!(addr == peer_addr1 || addr == peer_addr2 || addr == peer_addr3);
        }
    }

    #[test]
    fn test_pick_send_value() {
        let p2p_addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17029);
        let (_, _, generator,  _, _, locked_peers, _) = new_server_env(p2p_addr_1);

        let peer_addr1 = generate_random_h160();
        let peer_addr2 = generate_random_h160();
        let peer_addr3 = generate_random_h160();

        let mut peers = locked_peers.lock().unwrap();
        peers.insert(&peer_addr1);
        let mut peer_num = peers.addrs.len();
        drop(peers);

        let mut portion = min(peer_num + 1, VALID_OUTPUTS_NUM);

        let total_1 = COINBASE_REWARD;
        let res_1 =generator.pick_send_value(total_1, portion);
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

        portion = min(peer_num + 1, VALID_OUTPUTS_NUM);

        //Set a large number to avoid duplicate
        let total_2 = 50 * COINBASE_REWARD;
        for _ in 0..REPEAT_TEST_TIME {
            let res_2 =generator.pick_send_value(total_2, portion);
            assert_eq!(peer_num, 3);
            assert_eq!(res_2.len(), VALID_OUTPUTS_NUM);
            let sum_2: u64 = res_2.iter().sum();
            assert_eq!(sum_2, 50 * COINBASE_REWARD);
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