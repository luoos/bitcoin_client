use crate::network::server::Handle as ServerHandle;

use log::info;

use crossbeam::channel::{unbounded, Receiver, Sender, TryRecvError};
use std::time;
use std::time::SystemTime;

use std::thread;
use std::sync::{Arc, Mutex};
use ring::signature::Ed25519KeyPair;

use crate::blockchain::Blockchain;
use crate::block::{Header, Block};
use crate::network::message::{Message};
use crate::crypto::hash::H256;
use crate::config::MINING_STEP;
use crate::mempool::MemPool;

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
    mempool: Arc<Mutex<MemPool>>,
    pub nonce: u32,
    pub mined_num: usize,
    key_pair: Arc<Ed25519KeyPair>,
}

#[derive(Clone)]
pub struct Handle {
    /// Channel for sending signal to the miner thread
    control_chan: Sender<ControlSignal>,
}

pub fn new(
    server: ServerHandle,
    blockchain: Arc<Mutex<Blockchain>>,
    mempool: Arc<Mutex<MemPool>>,
    key_pair: Arc<Ed25519KeyPair>,
) -> (Context, Handle) {
    let (signal_chan_sender, signal_chan_receiver) = unbounded();

    let ctx = Context {
        control_chan: signal_chan_receiver,
        operating_state: OperatingState::Paused,
        server: server,
        blockchain: blockchain,
        mempool: mempool,
        nonce: 0,
        mined_num: 0,
        key_pair: key_pair,
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

    // Procedures when new block found
    pub(crate) fn found(&mut self, block: Block) {
        self.mined_num += 1;
        info!("Mined a block: {:?}, number of transactions: {:?}. Total mined: {}",
                block.hash, block.content.trans.len(), self.mined_num);

        let hash_of_trans = block.content.get_trans_hashes();
        // insert block into chain
        let mut blockchain = self.blockchain.lock().unwrap();
        blockchain.insert(&block);
        drop(blockchain);

        // remove content's all transactions from mempool
        let mut mempool = self.mempool.lock().unwrap();
        mempool.remove_trans(&hash_of_trans);
        mempool.remove_conflict_tx_inputs(&block.content);

        // broadcast new block
        let vec = vec![block.hash.clone()];
        self.server.broadcast(Message::NewBlockHashes(vec), None);
    }

    // Mining process! Return true: mining a block successfully
    fn mining(&mut self) -> bool {
        let blockchain = self.blockchain.lock().unwrap();
        let tip = blockchain.tip();  // previous hash
        let difficulty = blockchain.difficulty();
        drop(blockchain);

        let mempool = self.mempool.lock().unwrap();

        // Miner put transactions into block content from mempool!!
        let content = mempool.create_content(&self.key_pair);
        drop(mempool);

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
}

// Perforn mining for MINING_STEP here
pub fn mining_base(header: &mut Header, difficulty: H256) -> bool {
    for _ in 0..MINING_STEP {
        if header.hash() < difficulty {
            return true;
        }
        header.change_nonce();
    }
    return false;
}

#[cfg(any(test, test_utilities))]
pub mod tests {
    use crate::miner;
    use crate::crypto::hash::H256;
    use crate::helper::*;

    use std::time;
    use std::thread;
    use std::net::{SocketAddr, IpAddr, Ipv4Addr};
    use crate::config::{BLOCK_SIZE_LIMIT, EASIEST_DIF};
    use crate::spread::Spreader;

    #[test]
    fn test_miner() {
        let p2p_addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17010);
        let (_server_handle, mut miner, _, _blockchain, mempool, _, _) = new_server_env(p2p_addr_1, Spreader::Default, false);

        //Must-be-done difficulty
        let mut difficulty: H256 = gen_difficulty_array(0).into();
        miner.change_difficulty(&difficulty);
        let mut pool = mempool.lock().unwrap();
        for _ in 0..BLOCK_SIZE_LIMIT {
            let new_t = generate_random_signed_transaction();
            pool.add_with_check(&new_t);
        }
        drop(pool);
        assert_eq!(0, miner.nonce);
        assert!(miner.mining());
        assert_eq!(0, miner.nonce);

        //Impossible difficulty
        difficulty = gen_difficulty_array(256).into();
        miner.change_difficulty(&difficulty);
        let mut pool = mempool.lock().unwrap();
        for _ in 0..BLOCK_SIZE_LIMIT {
            let new_t = generate_random_signed_transaction();
            pool.add_with_check(&new_t);
        }
        drop(pool);
        assert!(!miner.mining());
        assert_eq!(miner::MINING_STEP, miner.nonce);
    }

    #[test]
    fn test_block_relay() {
        let p2p_addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17011);
        let p2p_addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17012);
        let p2p_addr_3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17013);

        let (_server_1, mut miner_ctx_1, _, blockchain_1, _mempool_1, _, _) = new_server_env(p2p_addr_1, Spreader::Default, false);
        let (server_2, mut miner_ctx_2, _, blockchain_2, _mempool_2, _, _) = new_server_env(p2p_addr_2, Spreader::Default, false);
        let (server_3, mut miner_ctx_3, _, blockchain_3, _mempool_3, _, _) = new_server_env(p2p_addr_3, Spreader::Default, false);
        blockchain_1.lock().unwrap().set_check_trans(false);
        blockchain_2.lock().unwrap().set_check_trans(false);
        blockchain_3.lock().unwrap().set_check_trans(false);

        // bilateral connection!!
        let peers_1 = vec![p2p_addr_1];
        connect_peers(&server_2, &peers_1);
        let peers_2 = vec![p2p_addr_2];
        connect_peers(&server_3, &peers_2);

        let chain_1 = blockchain_1.lock().unwrap();
        let difficulty = chain_1.difficulty();
        let new_block_1 = generate_mined_block(&chain_1.tip(), &difficulty);
        drop(chain_1);
        miner_ctx_1.found(new_block_1);
        thread::sleep(time::Duration::from_millis(100));

        // test block broadcast
        let chain_1 = blockchain_1.lock().unwrap();
        let chain_2 = blockchain_2.lock().unwrap();
        let chain_3 = blockchain_3.lock().unwrap();
        assert_eq!(chain_1.length(), 2);
        assert_eq!(chain_1.length(), chain_2.length());
        assert_eq!(chain_1.length(), chain_3.length());
        assert_eq!(chain_1.get_block(&chain_1.tip()), chain_2.get_block(&chain_2.tip()));
        assert_eq!(chain_1.get_block(&chain_1.tip()), chain_3.get_block(&chain_3.tip()));
        drop(chain_1);
        drop(chain_2);
        drop(chain_3);

        let chain_2 = blockchain_1.lock().unwrap();
        let new_block_2 = generate_mined_block(&chain_2.tip(), &difficulty);
        miner_ctx_2.found(new_block_2);
        drop(chain_2);
        thread::sleep(time::Duration::from_millis(100));

        let chain_1 = blockchain_1.lock().unwrap();
        let chain_2 = blockchain_2.lock().unwrap();
        let chain_3 = blockchain_3.lock().unwrap();
        assert_eq!(chain_1.length(), 3);
        assert_eq!(chain_1.length(), chain_2.length());
        assert_eq!(chain_1.length(), chain_3.length());
        assert_eq!(chain_1.get_block(&chain_1.tip()), chain_2.get_block(&chain_2.tip()));
        assert_eq!(chain_1.get_block(&chain_1.tip()), chain_3.get_block(&chain_3.tip()));
        drop(chain_1);
        drop(chain_2);
        drop(chain_3);

        let chain_3 = blockchain_1.lock().unwrap();
        let new_block_3 = generate_mined_block(&chain_3.tip(), &difficulty);
        miner_ctx_3.found(new_block_3);
        drop(chain_3);
        thread::sleep(time::Duration::from_millis(100));

        let chain_1 = blockchain_1.lock().unwrap();
        let chain_2 = blockchain_2.lock().unwrap();
        let chain_3 = blockchain_3.lock().unwrap();
        assert_eq!(chain_1.length(), 4);
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
        let new_block_1 = generate_mined_block(&chain_1.tip(), &difficulty);
        chain_1.insert(&new_block_1);
        drop(chain_1);
        assert_eq!(5, blockchain_1.lock().unwrap().length());
        assert_eq!(4, blockchain_2.lock().unwrap().length());
        assert_eq!(4, blockchain_3.lock().unwrap().length());

        let new_block_2 = generate_mined_block(&new_block_1.hash, &difficulty);
        miner_ctx_1.found(new_block_2);
        thread::sleep(time::Duration::from_millis(100));
        assert_eq!(6, blockchain_1.lock().unwrap().length());
        assert_eq!(6, blockchain_2.lock().unwrap().length());
        assert_eq!(6, blockchain_3.lock().unwrap().length());

        // test insert_with_check
        let mut chain_1 = blockchain_1.lock().unwrap();
        let wrong_difficulty: H256 = gen_difficulty_array(1).into();
        let wrong_block = generate_mined_block(&chain_1.tip(), &wrong_difficulty);
        assert!(!chain_1.insert_with_check(&wrong_block));
        assert!(!chain_1.insert_with_check(&new_block_1));
        let correct_difficulty: H256 = gen_difficulty_array(EASIEST_DIF).into();
        let correct_block = generate_mined_block(&chain_1.tip(), &correct_difficulty);
        assert!(chain_1.insert_with_check(&correct_block));
    }
}