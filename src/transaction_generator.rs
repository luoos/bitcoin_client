use std::sync::{Arc, Mutex};
use std::thread;
use std::time;
use log::info;
use rand::Rng;

use crate::network::server::Handle as ServerHandle;
use crate::network::message::Message;
use crate::mempool::MemPool;
use crate::helper;
use crate::crypto::hash::H160;
use crate::config::{TRANSACTION_GENERATE_INTERVAL};
use crate::peers::Peers;
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
            if let Some(rec_addr) = self.random_peer_addr() {
                if let Some(tran) = helper::generate_valid_tran(&state, &self.account, &rec_addr) {
                    let mut mempool = self.mempool.lock().unwrap();
                    if mempool.add_with_check(&tran) {
                        info!("Put a new transaction into client! Now mempool has {} transaction", mempool.size());
                        let vec = vec![tran.hash.clone()];
                        self.server.broadcast(Message::NewTransactionHashes(vec));
                    }
                }
            }
            let sleep_itv = time::Duration::from_millis(TRANSACTION_GENERATE_INTERVAL);
            thread::sleep(sleep_itv);
        }
    }

    // Pick single random peer to as receiver of new transaction
    fn random_peer_addr(&self) -> Option<H160> {
        let peers = self.peers.lock().unwrap();
        let peer_addrs = peers.addrs.clone();
        drop(peers);
        let peer_num = peer_addrs.len();

        let mut rng = rand::thread_rng();

        if peer_num == 0 {
            return None;
        } else {
            let mut num = rng.gen_range(0, peer_num);
            for addr in peer_addrs.iter() {
                if num == 0 {
                    return Some(addr.clone());
                }
                num -= 1;
            }
        }
        None
    }

    #[cfg(any(test, test_utilities))]
    pub fn generating(&mut self) {
        let new_t = helper::generate_random_signed_transaction_from_keypair(&self.account.key_pair);
        let mut mempool = self.mempool.lock().unwrap();
        if mempool.add_with_check(&new_t) {
            let vec = vec![new_t.hash.clone()];
            self.server.broadcast(Message::NewTransactionHashes(vec));
        }
        drop(mempool);
    }
}

#[cfg(any(test, test_utilities))]
mod tests {
    use std::net::{SocketAddr, IpAddr, Ipv4Addr};
    use std::thread::sleep;
    use std::time;

    use crate::helper::*;
    use crate::config::REPEAT_TEST_TIME;
    use crate::spread::Spreader;

    #[test]
    fn test_transaction_relay() {
        let p2p_addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17021);
        let p2p_addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17022);
        let p2p_addr_3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17023);

        let (_server_1, _miner_ctx_1, mut generator_1,  _blockchain_1, mempool_1, _, _) = new_server_env(p2p_addr_1, Spreader::Default);
        let (server_2, _miner_ctx_2, mut generator_2, _blockchain_2, mempool_2, _, _) = new_server_env(p2p_addr_2, Spreader::Default);
        let (server_3, _miner_ctx_3, mut generator_3, _blockchain_3, mempool_3, _, _) = new_server_env(p2p_addr_3, Spreader::Default);

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
    fn test_random_peer_addr() {
        let p2p_addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17028);
        let (_, _, generator,  _, _, locked_peers, _) = new_server_env(p2p_addr_1, Spreader::Default);

        let peer_addr1 = generate_random_h160();
        let peer_addr2 = generate_random_h160();
        let peer_addr3 = generate_random_h160();

        let mut peers = locked_peers.lock().unwrap();
        peers.insert(&peer_addr1);
        peers.insert(&peer_addr2);
        peers.insert(&peer_addr3);
        drop(peers);

        for _ in 0..REPEAT_TEST_TIME {
            assert!(generator.random_peer_addr().is_some());
            let addr = generator.random_peer_addr().unwrap();
            assert!(addr == peer_addr1 || addr == peer_addr2 || addr == peer_addr3);
        }
    }
}