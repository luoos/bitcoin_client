use std::sync::{Arc, Mutex};
use std::thread;
use std::time;
use log::info;
use rand::Rng;
use crossbeam::channel::{unbounded, Receiver, Sender, TryRecvError};

use crate::network::server::Handle as ServerHandle;
use crate::network::message::Message;
use crate::mempool::MemPool;
use crate::helper;
use crate::crypto::hash::H160;
use crate::config::TRANSACTION_GENERATE_INTERVAL;
use crate::peers::Peers;
use crate::blockchain::Blockchain;
use crate::account::Account;

enum ControlSignal {
    Start(u64), // the number controls the interval to generate new tx
    Exit,
    Paused,
}

enum OperatingState {
    Run(u64),
    Paused,
    ShutDown,
}

pub struct Context {
    control_chan: Receiver<ControlSignal>,
    operating_state: OperatingState,
    server: ServerHandle,
    mempool: Arc<Mutex<MemPool>>,
    blockchain: Arc<Mutex<Blockchain>>,
    peers: Arc<Mutex<Peers>>,
    account: Arc<Account>,
    dandelion: bool,
}

#[derive(Clone)]
pub struct Handle {
    /// Channel for sending signal to the tx_generating thread
    control_chan: Sender<ControlSignal>,
}

pub fn new(
    server: ServerHandle,
    mempool: Arc<Mutex<MemPool>>,
    blockchain: Arc<Mutex<Blockchain>>,
    peers: Arc<Mutex<Peers>>,
    account: Arc<Account>,
    dandelion: bool,
) -> (Context, Handle) {
    let (signal_chan_sender, signal_chan_receiver) = unbounded();

    let ctx = Context {
        control_chan: signal_chan_receiver,
        operating_state: OperatingState::Run(TRANSACTION_GENERATE_INTERVAL),
        server,
        mempool,
        blockchain,
        peers,
        account,
        dandelion,
    };

    let handle = Handle {
        control_chan: signal_chan_sender,
    };

    (ctx, handle)
}

impl Handle {
    pub fn exit(&self) {
        self.control_chan.send(ControlSignal::Exit).unwrap();
    }

    pub fn start(&self, itv: u64) {
        self.control_chan
            .send(ControlSignal::Start(itv))
            .unwrap();
    }

    pub fn stop(&self) {
        self.control_chan
            .send(ControlSignal::Exit)
            .unwrap()
    }

    pub fn pause(&self) {
        self.control_chan
            .send(ControlSignal::Paused)
            .unwrap()
    }
}

impl Context {
    pub fn start(mut self) {
        thread::Builder::new()
            .name("transaction_generator".to_string())
            .spawn(move || {
                self.transaction_generator_loop();
            })
            .unwrap();
        info!("Transaction generator Started");
    }

    fn handle_control_signal(&mut self, signal: ControlSignal) {
        match signal {
            ControlSignal::Start(i) => {
                info!("Transaction_generator starting in continuous mode");
                self.operating_state = OperatingState::Run(i);
            }
            ControlSignal::Exit => {
                info!("Transaction_generator shutting down");
                self.operating_state = OperatingState::ShutDown;
            }
            ControlSignal::Paused => {
                info!("Transaction_generator paused");
                self.operating_state = OperatingState::Paused;
            }
        }
    }

    fn transaction_generator_loop(&mut self) {
        loop {
            match self.operating_state {
                OperatingState::Paused => {
                    let signal = self.control_chan.recv().unwrap();
                    self.handle_control_signal(signal);
                    continue;
                }
                OperatingState::ShutDown => {
                    return;
                }
                _ => match self.control_chan.try_recv() {
                    Ok(signal) => {
                        self.handle_control_signal(signal);
                    }
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => panic!("Transaction_generator control channel detached"),
                },
            }
            if let OperatingState::ShutDown = self.operating_state {
                return;
            }

            self.tx_generating();

            if let OperatingState::Run(i) = self.operating_state {
                if i != 0 {
                    let sleep_itv = time::Duration::from_millis(i as u64);
                    thread::sleep(sleep_itv);
                }
            }
        }
    }

    // Generating logic method!
    fn tx_generating(&mut self) {
        // Update state from tip of longest-chain
        let state = self.blockchain.lock().unwrap().tip_block_state();
        if let Some(rec_addr) = self.random_peer_addr() {
            if let Some(tran) = helper::generate_valid_tran(&state, &self.account, &rec_addr) {
                let mut mempool = self.mempool.lock().unwrap();
                if mempool.add_with_check(&tran) {
                    info!("Put a new transaction into client! Now mempool has {} transaction", mempool.size());
                    if self.dandelion {
                        let vec_trans = vec![tran];
                        self.server.broadcast(Message::NewDandelionTransactions(vec_trans), None);
                    } else {
                        let vec_hash = vec![tran.hash.clone()];
                        self.server.broadcast(Message::NewTransactionHashes(vec_hash), None);
                    }
                }
            }
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
            if self.dandelion {
                let vec_trans = vec![new_t];
                self.server.broadcast(Message::NewDandelionTransactions(vec_trans), None);
            } else {
                let vec_hash = vec![new_t.hash.clone()];
                self.server.broadcast(Message::NewTransactionHashes(vec_hash), None);
            }
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
    use crate::crypto::key_pair;
    use ring::signature::{ED25519_PUBLIC_KEY_LEN, KeyPair};

    #[test] #[ignore]  // flaky
    fn test_transaction_relay() {
        let p2p_addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17021);
        let p2p_addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17022);
        let p2p_addr_3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17023);

        let (_server_1, _miner_ctx_1, mut generator_1,  _blockchain_1, mempool_1, _, _) = new_server_env(p2p_addr_1, Spreader::Default, false);
        let (server_2, _miner_ctx_2, mut generator_2, _blockchain_2, mempool_2, _, _) = new_server_env(p2p_addr_2, Spreader::Default, false);
        let (server_3, _miner_ctx_3, mut generator_3, _blockchain_3, mempool_3, _, _) = new_server_env(p2p_addr_3, Spreader::Default, false);

        let peers_1 = vec![p2p_addr_1];
        connect_peers(&server_2, &peers_1);
        let peers_2 = vec![p2p_addr_2];
        connect_peers(&server_3, &peers_2);

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

    #[test] #[ignore] // flaky
    fn test_supernode_no_relay_trans() {
        let p2p_addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17085);
        let p2p_addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17086);
        let p2p_addr_3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17087);

        let (_server_1, _miner_ctx_1, mut generator_1,  _blockchain_1, mempool_1, _, _) = new_server_env(p2p_addr_1, Spreader::Default, false);
        // server 2 is supernode
        let (server_2, _miner_ctx_2, _, _blockchain_2, mempool_2, _, _) = new_server_env(p2p_addr_2, Spreader::Default, true);
        let (server_3, _miner_ctx_3, mut generator_3, _blockchain_3, mempool_3, _, _) = new_server_env(p2p_addr_3, Spreader::Default, false);

        let peers_1 = vec![p2p_addr_1];
        connect_peers(&server_2, &peers_1);
        let peers_2 = vec![p2p_addr_2];
        connect_peers(&server_3, &peers_2);

        generator_1.generating();
        sleep(time::Duration::from_millis(100));

        let pool_1 = mempool_1.lock().unwrap();
        let pool_2 = mempool_2.lock().unwrap();
        let pool_3 = mempool_3.lock().unwrap();
        assert_eq!(pool_1.size(), 1);
        assert_eq!(pool_1.size(), pool_2.size());
        assert_eq!(pool_3.size(), 0);
        drop(pool_1);
        drop(pool_2);
        drop(pool_3);

        generator_3.generating();
        sleep(time::Duration::from_millis(100));

        let pool_1 = mempool_1.lock().unwrap();
        let pool_2 = mempool_2.lock().unwrap();
        let pool_3 = mempool_3.lock().unwrap();
        assert_eq!(pool_1.size(), 1);
        assert_eq!(pool_2.size(), 2);
        assert_eq!(pool_3.size(), 1);
        drop(pool_1);
        drop(pool_2);
        drop(pool_3);
    }

    #[test]
    fn test_random_peer_addr() {
        let p2p_addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17028);
        let (_, _, generator,  _, _, locked_peers, _) = new_server_env(p2p_addr_1, Spreader::Default, false);

        let peer_addr1 = generate_random_h160();
        let peer_addr2 = generate_random_h160();
        let peer_addr3 = generate_random_h160();

        let peer_key_pair1 = key_pair::random();
        let peer_key_pair2 = key_pair::random();
        let peer_key_pair3 = key_pair::random();

        let mut bytes_pub_key1: [u8; ED25519_PUBLIC_KEY_LEN] = [0; ED25519_PUBLIC_KEY_LEN];
        bytes_pub_key1[..].copy_from_slice(&peer_key_pair1.public_key().as_ref()[..]);
        let mut bytes_pub_key2: [u8; ED25519_PUBLIC_KEY_LEN] = [0; ED25519_PUBLIC_KEY_LEN];
        bytes_pub_key2[..].copy_from_slice(&peer_key_pair2.public_key().as_ref()[..]);
        let mut bytes_pub_key3: [u8; ED25519_PUBLIC_KEY_LEN] = [0; ED25519_PUBLIC_KEY_LEN];
        bytes_pub_key3[..].copy_from_slice(&peer_key_pair3.public_key().as_ref()[..]);

        let port1 = 1111u16;
        let port2 = 2222u16;
        let port3 = 3333u16;

        let mut peers = locked_peers.lock().unwrap();
        peers.insert(&peer_addr1, Box::new(bytes_pub_key1), port1);
        peers.insert(&peer_addr2, Box::new(bytes_pub_key2), port2);
        peers.insert(&peer_addr3, Box::new(bytes_pub_key3), port3);
        drop(peers);

        for _ in 0..REPEAT_TEST_TIME {
            assert!(generator.random_peer_addr().is_some());
            let addr = generator.random_peer_addr().unwrap();
            assert!(addr == peer_addr1 || addr == peer_addr2 || addr == peer_addr3);
        }
    }
}