use crate::network::server::Handle as ServerHandle;

use log::info;

use crossbeam::channel::{unbounded, Receiver, Sender, TryRecvError};
use std::time;
use std::time::SystemTime;

use std::thread;
use std::sync::{Arc, Mutex};
use rand::thread_rng;
use rand::distributions::Distribution;

use crate::blockchain::Blockchain;
use crate::transaction::Transaction;
use crate::block::{Content, Header, Block};
use crate::network::message::{Message};
use crate::crypto::hash::H256;
use crate::config::MINING_STEP;

static DEMO_TRANS: usize = 4;

enum ControlSignal {
    Start(u64), // the number controls the lambda of interval between block generation
    Exit,
    Paused,
}

enum OperatingState {
    Paused,
    Run(u64),
    ShutDown,
}

pub struct Context {
    /// Channel for receiving control signal
    control_chan: Receiver<ControlSignal>,
    operating_state: OperatingState,
    server: ServerHandle,
    blockchain: Arc<Mutex<Blockchain>>,
    trans: Arc<Mutex<Vec<Transaction>>>,
    pub nonce: u32,
    pub mined_num: usize,
}

#[derive(Clone)]
pub struct Handle {
    /// Channel for sending signal to the miner thread
    control_chan: Sender<ControlSignal>,
}

pub fn new(
    server: &ServerHandle,
    blockchain: &Arc<Mutex<Blockchain>>,
) -> (Context, Handle) {
    let (signal_chan_sender, signal_chan_receiver) = unbounded();

    let trans = Arc::new(Mutex::new(Vec::<Transaction>::new()));
    let ctx = Context {
        control_chan: signal_chan_receiver,
        operating_state: OperatingState::Paused,
        server: server.clone(),
        blockchain: Arc::clone(blockchain),
        trans: trans,
        nonce: 0,
        mined_num: 0,
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

    pub fn start(&self, lambda: u64) {
        self.control_chan
            .send(ControlSignal::Start(lambda))
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
            .name("miner".to_string())
            .spawn(move || {
                self.miner_loop();
            })
            .unwrap();
        info!("Miner initialized into paused mode");
    }

    fn handle_control_signal(&mut self, signal: ControlSignal) {
        match signal {
            ControlSignal::Exit => {
                info!("Miner shutting down");
                self.operating_state = OperatingState::ShutDown;
            }
            ControlSignal::Start(i) => {
                info!("Miner starting in continuous mode with lambda {}", i);
                self.operating_state = OperatingState::Run(i);
            }
            ControlSignal::Paused => {
                info!("Miner paused");
                self.operating_state = OperatingState::Paused;
            }
        }
    }

    fn miner_loop(&mut self) {
        // main mining loop
        loop {
            // check and react to control signals
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
                    Err(TryRecvError::Disconnected) => panic!("Miner control channel detached"),
                },
            }
            if let OperatingState::ShutDown = self.operating_state {
                return;
            }

            self.mining();

            if let OperatingState::Run(i) = self.operating_state {
                if i != 0 {
                    let interval = time::Duration::from_micros(i as u64);
                    thread::sleep(interval);
                }
            }
        }
    }

    fn found(&mut self, block: Block) {
        info!("Found block: {:?}", block);
        // insert block into chain
        let mut blockchain = self.blockchain.lock().unwrap();
        blockchain.insert(&block);
        drop(blockchain);

        // clear transactions
        let mut trans = self.trans.lock().unwrap();
        trans.clear();
        drop(trans);

        // add new mined block into total count
        self.mined_num += 1;
        info!("Mined {} blocks so far!", self.mined_num);

        // broadcast new block
        let vec = vec![block.hash.clone()];
        self.server.broadcast(Message::NewBlockHashes(vec));
    }

    fn mining(&mut self) -> bool {
        let blockchain = self.blockchain.lock().unwrap();
        let tip = blockchain.tip();  // previous hash
        let difficulty = blockchain.difficulty();
        drop(blockchain);

        let mut trans = self.trans.lock().unwrap();
        if trans.len() == 0 {
            // for demo
            for _ in 0..DEMO_TRANS {
                trans.push(generate_random_transaction());
            }
        }
        let content = Content::new_with_trans(&trans);
        drop(trans);

        let nonce = self.nonce;
        let ts = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
                .unwrap().as_millis();
        let mut header = Header::new(&tip, nonce, ts,
                &difficulty, &content.merkle_root());

        let mut bingo = false;
        if mining_base(&mut header, difficulty) {
            let block = Block::new(header, content);
            self.found(block);
            bingo = true;
            self.nonce = 0;
        } else {
            self.nonce = header.nonce;
        }
        bingo
    }

    #[cfg(any(test, test_utilities))]
    fn change_difficulty(&mut self, new_difficulty: &H256) {
        let mut blockchain = self.blockchain.lock().unwrap();
        blockchain.change_difficulty(new_difficulty);
    }

    #[cfg(any(test, test_utilities))]
    fn trans_len(&self) -> usize {
        let trans = self.trans.lock().unwrap();
        trans.len()
    }
}

fn mining_base(header: &mut Header, difficulty: H256) -> bool {
    for _ in 0..MINING_STEP {
        if header.hash() < difficulty {
            return true;
        }
        header.change_nonce();
    }
    return false;
}

// for demo
fn generate_random_str() -> String {
    let rng = thread_rng();
    rand::distributions::Alphanumeric.sample_iter(rng).take(10).collect()
}

// for demo
pub fn generate_random_transaction() -> Transaction {
    Transaction {msg: generate_random_str()}
}

#[cfg(any(test, test_utilities))]
mod tests {
    use crate::blockchain::Blockchain;
    use crate::miner;
    use crate::crypto::hash::H256;
    use crate::network::{worker, server};
    use crate::block::test::generate_random_block;

    use log::{error, info};
    use std::sync::{Arc, Mutex};
    use std::time;
    use std::thread;
    use std::net::{SocketAddr, IpAddr, Ipv4Addr};
    use crossbeam::channel;

    #[test]
    fn test_miner() {
        let p2p_addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17010);
        let (_server_handle, mut miner, _blockchain) = new_server_env(p2p_addr_1);
        let mut difficulty: H256 = H256::from([255u8; 32]);
        miner.change_difficulty(&difficulty);
        assert_eq!(0, miner.nonce);
        assert!(miner.mining());
        assert_eq!(0, miner.nonce);
        assert_eq!(0, miner.trans_len());
        difficulty = H256::from([0u8; 32]);
        miner.change_difficulty(&difficulty);
        assert!(!miner.mining());
        assert_eq!(miner::MINING_STEP, miner.nonce);
        assert_eq!(miner::DEMO_TRANS, miner.trans_len());
        difficulty = H256::from([255u8; 32]);
        miner.change_difficulty(&difficulty);
        assert!(miner.mining());
        assert_eq!(0, miner.nonce);
        assert_eq!(0, miner.trans_len());
    }

    #[test]
    fn test_block_relay() {
        let p2p_addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17011);
        let p2p_addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17012);
        let p2p_addr_3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17013);

        let (_server_1, mut miner_ctx_1, blockchain_1) = new_server_env(p2p_addr_1);
        let (server_2, mut miner_ctx_2, blockchain_2) = new_server_env(p2p_addr_2);
        let (server_3, mut miner_ctx_3, blockchain_3) = new_server_env(p2p_addr_3);

        // bilateral connection!!
        let peers_1 = vec![p2p_addr_1];
        connect_peers(&server_2, peers_1.clone());
        let peers_2 = vec![p2p_addr_2];
        connect_peers(&server_3, peers_2.clone());

        let chain_1 = blockchain_1.lock().unwrap();
        let new_block_1 = generate_random_block(&chain_1.tip());
        drop(chain_1);
        miner_ctx_1.found(new_block_1);
        thread::sleep(time::Duration::from_millis(200));

        let chain_1 = blockchain_1.lock().unwrap();
        let chain_2 = blockchain_2.lock().unwrap();
        let chain_3 = blockchain_3.lock().unwrap();
        assert!(chain_1.length() == 2);
        assert_eq!(chain_1.length(), chain_2.length());
        assert_eq!(chain_1.length(), chain_3.length());
        assert_eq!(chain_1.get_block(&chain_1.tip()), chain_2.get_block(&chain_2.tip()));
        assert_eq!(chain_1.get_block(&chain_1.tip()), chain_3.get_block(&chain_3.tip()));
        drop(chain_1);
        drop(chain_2);
        drop(chain_3);

        let chain_2 = blockchain_1.lock().unwrap();
        let new_block_2 = generate_random_block(&chain_2.tip());
        miner_ctx_2.found(new_block_2);
        drop(chain_2);
        thread::sleep(time::Duration::from_millis(200));

        let chain_1 = blockchain_1.lock().unwrap();
        let chain_2 = blockchain_2.lock().unwrap();
        let chain_3 = blockchain_3.lock().unwrap();
        assert!(chain_1.length() == 3);
        assert_eq!(chain_1.length(), chain_2.length());
        assert_eq!(chain_1.length(), chain_3.length());
        assert_eq!(chain_1.get_block(&chain_1.tip()), chain_2.get_block(&chain_2.tip()));
        assert_eq!(chain_1.get_block(&chain_1.tip()), chain_3.get_block(&chain_3.tip()));
        drop(chain_1);
        drop(chain_2);
        drop(chain_3);

        let chain_3 = blockchain_1.lock().unwrap();
        let new_block_3 = generate_random_block(&chain_3.tip());
        miner_ctx_3.found(new_block_3);
        drop(chain_3);
        thread::sleep(time::Duration::from_millis(200));

        let chain_1 = blockchain_1.lock().unwrap();
        let chain_2 = blockchain_2.lock().unwrap();
        let chain_3 = blockchain_3.lock().unwrap();
        assert!(chain_1.length() == 4);
        assert_eq!(chain_1.length(), chain_2.length());
        assert_eq!(chain_1.length(), chain_3.length());
        assert_eq!(chain_1.get_block(&chain_1.tip()), chain_2.get_block(&chain_2.tip()));
        assert_eq!(chain_1.get_block(&chain_1.tip()), chain_3.get_block(&chain_3.tip()));

        let total_mined_num : usize = miner_ctx_1.mined_num + miner_ctx_2.mined_num + miner_ctx_3.mined_num;
        assert_eq!(chain_1.length(), total_mined_num + 1);
        drop(chain_1);
        drop(chain_2);
        drop(chain_3);

        // test get missing parent
        let mut chain_1 = blockchain_1.lock().unwrap();
        let new_block_1 = generate_random_block(&chain_1.tip());
        chain_1.insert(&new_block_1);
        drop(chain_1);
        assert_eq!(5, blockchain_1.lock().unwrap().length());
        assert_eq!(4, blockchain_2.lock().unwrap().length());
        assert_eq!(4, blockchain_3.lock().unwrap().length());

        let new_block_2 = generate_random_block(&new_block_1.hash);
        miner_ctx_1.found(new_block_2);
        thread::sleep(time::Duration::from_millis(300));
        assert_eq!(6, blockchain_1.lock().unwrap().length());
        assert_eq!(6, blockchain_2.lock().unwrap().length());
        assert_eq!(6, blockchain_3.lock().unwrap().length());

    }

    fn new_server_env(ipv4_addr: SocketAddr) -> (server::Handle, miner::Context, Arc<Mutex<Blockchain>>) {
        let (sender, receiver) = channel::unbounded();
        let (server_ctx, server) = server::new(ipv4_addr, sender).unwrap();
        server_ctx.start().unwrap();

        let blockchain =  Arc::new(Mutex::new(Blockchain::new()));
        let worker_ctx = worker::new(4, receiver, &server, &blockchain);
        worker_ctx.start();

        let (miner_ctx, _miner) = miner::new(&server, &blockchain);

        (server, miner_ctx, blockchain)
    }

    fn connect_peers(server: &server::Handle, known_peers: Vec<SocketAddr>) {
        for peer_addr in known_peers {
            match server.connect(peer_addr) {
                Ok(_) => {
                    info!("Connected to outgoing peer {}", &peer_addr);
                }
                Err(e) => {
                    error!(
                        "Error connecting to peer {}, retrying in one second: {}",
                        peer_addr, e
                    );
                }
            }
        }
    }
}