use crossbeam::channel;
use log::{debug, warn};

use std::thread;
use std::sync::{Arc, Mutex};

use super::message::Message;
use super::peer;
use crate::network::server::Handle as ServerHandle;
use crate::blockchain::Blockchain;
use crate::crypto::hash::H256;

#[derive(Clone)]
pub struct Context {
    msg_chan: channel::Receiver<(Vec<u8>, peer::Handle)>,
    num_worker: usize,
    server: ServerHandle,
    blockchain: Arc<Mutex<Blockchain>>,
}

pub fn new(
    num_worker: usize,
    msg_src: channel::Receiver<(Vec<u8>, peer::Handle)>,
    server: &ServerHandle,
    blockchain: &Arc<Mutex<Blockchain>>,
) -> Context {
    Context {
        msg_chan: msg_src,
        num_worker,
        server: server.clone(),
        blockchain: Arc::clone(blockchain),
    }
}

impl Context {
    pub fn start(self) {
        let num_worker = self.num_worker;
        for i in 0..num_worker {
            let cloned = self.clone();
            thread::spawn(move || {
                cloned.worker_loop();
                warn!("Worker thread {} exited", i);
            });
        }
    }

    fn worker_loop(&self) {
        loop {
            let msg = self.msg_chan.recv().unwrap();
            let (msg, peer) = msg;
            let msg: Message = bincode::deserialize(&msg).unwrap();
            match msg {
                Message::Ping(nonce) => {
                    debug!("Ping: {}", nonce);
                    peer.write(Message::Pong(nonce.to_string()));
                }
                Message::Pong(nonce) => {
                    debug!("Pong: {}", nonce);
                }
                Message::NewBlockHashes(hashes) => {
                    debug!("NewBlockHashes: {:?}", hashes);
                    let blockchain = self.blockchain.lock().unwrap();
                    let to_get: Vec<H256> = hashes.into_iter()
                                .filter(|h| !blockchain.exist(h))
                                .collect();
                    drop(blockchain);
                    if to_get.len() > 0 {
                        peer.write(Message::GetBlocks(to_get));
                    }
                }
                Message::GetBlocks(hashes) => {
                    debug!("GetBlocks: {:?}", hashes);
                    let blocks = self.blockchain.lock().unwrap().get_blocks(&hashes);
                    if blocks.len() > 0 {
                        peer.write(Message::Blocks(blocks));
                    }
                }
                Message::Blocks(blocks) => {
                    debug!("Blocks: {:?}", blocks);
                    let mut blockchain = self.blockchain.lock().unwrap();
                    let mut new_hashes = Vec::<H256>::new();
                    let mut missing_parents = Vec::<H256>::new();
                    for b in blocks.iter() {
                        if blockchain.insert(b) {
                            new_hashes.push(b.hash.clone());
                        }
                        if let Some(parent_hash) = blockchain.missing_parent(&b.hash) {
                            missing_parents.push(parent_hash);
                        }
                    }
                    drop(blockchain);
                    if missing_parents.len() > 0 {
                        peer.write(Message::GetBlocks(missing_parents));
                    }
                    if new_hashes.len() > 0 {
                        self.server.broadcast(Message::NewBlockHashes(new_hashes));
                    }
                }
            }
        }
    }
}
