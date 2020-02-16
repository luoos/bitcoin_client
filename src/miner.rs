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

static MINE_STEP: u32 = 1024;

enum ControlSignal {
    Start(u64), // the number controls the lambda of interval between block generation
    Exit,
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
    nonce: u32,
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

            let blockchain = self.blockchain.lock().unwrap();
            let tip = blockchain.tip();
            let difficulty = blockchain.difficulty();
            drop(blockchain);

            let mut trans = self.trans.lock().unwrap();
            if trans.len() == 0 {
                // for demo
                for _ in 0..4 {
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

            let mut i: u32 = 0;
            while i < MINE_STEP {
                if header.hash() < difficulty {
                    // insert block into chain
                    let block = Block::new(header, content);
                    let mut blockchain = self.blockchain.lock().unwrap();
                    blockchain.insert(&block);
                    drop(blockchain);

                    // clear transactions
                    let mut trans = self.trans.lock().unwrap();
                    trans.clear();
                    drop(trans);

                    break;
                }
                header.change_nonce();
                i += 1;
            }
            self.nonce = self.nonce.overflowing_add(i).0;

            if let OperatingState::Run(i) = self.operating_state {
                if i != 0 {
                    let interval = time::Duration::from_micros(i as u64);
                    thread::sleep(interval);
                }
            }
        }
    }
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
