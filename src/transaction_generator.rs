use std::sync::{Arc, Mutex};
use std::thread;
use std::time;
use log::{info, debug};
use ring::signature::Ed25519KeyPair;

use crate::network::server::Handle as ServerHandle;
use crate::network::message::Message;
use crate::mempool::MemPool;
use crate::helper::{generate_signed_transaction, generate_random_signed_transaction_from_keypair};
use crate::crypto::hash::{Hashable, H160, H256};
use crate::config::TRANSACTION_GENERATE_INTERVAL;
use crate::block::State;
use crate::peers::Peers;
use std::collections::HashMap;
use rand::Rng;
use crate::transaction::{TxOutput, TxInput};
use crate::blockchain::Blockchain;

pub struct Context {
    server: ServerHandle,
    mempool: Arc<Mutex<MemPool>>,
    blockchain: Arc<Mutex<Blockchain>>,
    state: State,
    peers: Arc<Mutex<Peers>>,
    key_pair: Ed25519KeyPair,
    self_addr: H160,
}

pub fn new(
    server: &ServerHandle,
    mempool: &Arc<Mutex<MemPool>>,
    blockchain: &Arc<Mutex<Blockchain>>,
    state: &State,
    peers: &Arc<Mutex<Peers>>,
    key_pair: Ed25519KeyPair,
    self_addr: H160,
) -> Context {
    Context {
        server: server.clone(),
        mempool: Arc::clone(mempool),
        blockchain: Arc::clone(blockchain),
        state: state.clone(),
        peers: Arc::clone(peers),
        key_pair,
        self_addr,
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
        let new_t = generate_random_signed_transaction_from_keypair(&self.key_pair);
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

        // create value & receiver for this transaction
        let tx_output = self.pick_unspent_output();
        let peer_addr = self.pick_peer_addr();

        // Check prerequisite to generate a new transaction
        if let Some((input, output)) = tx_output {
            if let Some(peer_addr) = peer_addr {
                let mut rng = rand::thread_rng();
                let total_val = output.val;
                let send_val = rng.gen_range(1, total_val);

                let tx_inputs: Vec<TxInput> = vec![input];
                let tx_outputs: Vec<TxOutput> =
                    vec![TxOutput::new(peer_addr, send_val), TxOutput::new(self.self_addr, total_val - send_val)];

                let new_t = generate_signed_transaction(&self.key_pair, tx_inputs, tx_outputs);
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

    // Pick an TxOutput sent to user
    fn pick_unspent_output(&self) -> Option<(TxInput, TxOutput)> {
        let cur_state: HashMap<(H256, u32), (u64, H160)> = self.state.0.clone();

        for (input, output) in cur_state.iter() {
            // Arbitrary order traversal
            if output.1 == self.self_addr {
                return Some((TxInput::new(input.0, input.1), TxOutput::new(output.1, output.0)));
            }
        }
        None
    }

    // Pick random peer to as receiver of new transaction
    fn pick_peer_addr(&self) -> Option<H160> {
        let peers = self.peers.lock().unwrap();
        let peer_addrs = peers.addrs.clone();

        let peer_num = peer_addrs.len();
        if peer_num == 0 {
            return None;
        } else {
            // Arbitrary order traversal
            for addr in peers.addrs.iter() {
                return Some(addr.clone());
            }
        }
        debug!("pick_random_peer_addr: should not be here!!");
        drop(peers);
        None
    }

    // Get user's balance under current state
    #[allow(dead_code)]
    fn get_cur_balance(&self) -> u64 {
        let mut self_balance: u64 = 0;

        let cur_state: HashMap<(H256, u32), (u64, H160)> = self.state.0.clone();

        for (_, (val, rec_addr)) in cur_state.iter() {
            if rec_addr.clone() == self.self_addr {
                self_balance += val.clone();
            }
        }
        self_balance
    }
}

#[cfg(any(test, test_utilities))]
mod tests {
    use crate::helper::{new_server_env, connect_peers};
    use std::net::{SocketAddr, IpAddr, Ipv4Addr};
    use std::thread::sleep;
    use std::time;

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
}