use crossbeam::channel;
use log::{debug, warn};

use std::thread;
use std::sync::{Arc, Mutex};

use super::message::Message;
use super::peer;
use crate::network::server::Handle as ServerHandle;
use crate::blockchain::Blockchain;
use crate::crypto::hash::{H256, Hashable, H160};
use crate::mempool::MemPool;
use crate::peers::Peers;

use ring::signature::ED25519_PUBLIC_KEY_LEN;

#[derive(Clone)]
pub struct Context {
    msg_chan: channel::Receiver<(Vec<u8>, peer::Handle)>,
    num_worker: usize,
    server: ServerHandle,
    blockchain: Arc<Mutex<Blockchain>>,
    mempool: Arc<Mutex<MemPool>>,
    peers_info: Arc<Mutex<Peers>>,
    self_addr: H160,
    self_pub_key: Box<[u8; ED25519_PUBLIC_KEY_LEN]>,
    self_port: u16,
    supernode: bool,
}

pub fn new(
    num_worker: usize,
    msg_src: channel::Receiver<(Vec<u8>, peer::Handle)>,
    server: ServerHandle,
    blockchain: Arc<Mutex<Blockchain>>,
    mempool: Arc<Mutex<MemPool>>,
    peers_info: Arc<Mutex<Peers>>,
    self_addr: H160,
    self_pub_key: Box<[u8; ED25519_PUBLIC_KEY_LEN]>,
    self_port: u16
) -> Context {
    Context {
        msg_chan: msg_src,
        num_worker,
        server,
        blockchain,
        mempool,
        peers_info,
        self_addr,
        self_pub_key,
        self_port,
        supernode: false,
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

    pub fn as_supernode(&mut self) {
        self.supernode = true;
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
                    //Check whether the hashes are already in blockchain; if not,sending GetBlocks to ask for them.
                    debug!("NewBlockHashes message received!!: {:?}", hashes);
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
                    //Check whether the hashes are already in blockchain; if yes,sending the corresponding blocks thru Blocks.
                    debug!("GetBlocks message received: {:?}", hashes);
                    let blocks = self.blockchain.lock().unwrap().get_blocks(&hashes);
                    if blocks.len() > 0 {
                        peer.write(Message::Blocks(blocks));
                    }
                }
                Message::Blocks(blocks) => {
                    //Insert the blocks into blockchain if not already in it; also ask for missing parent blocks
                    debug!("Blocks message received!!");
                    let mut blockchain = self.blockchain.lock().unwrap();
                    let mut mempool = self.mempool.lock().unwrap();
                    let mut new_hashes = Vec::<H256>::new();
                    let mut missing_parents = Vec::<H256>::new();
                    for b in blocks.iter() {
                        if blockchain.insert_with_check(b) {
                            if !self.supernode {
                                mempool.remove_trans(&b.content.get_trans_hashes());
                            }
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
                Message::NewTransactionHashes(hashes) => {
                    //Check whether the transactions are already in mempool/blockchain; if not,sending GetTransactions to ask for them.
                    debug!("NewTransactionHashes message received: {:?}", hashes);
                    let mempool  = self.mempool.lock().unwrap();
                    let to_get: Vec<H256> = hashes.into_iter()
                                .filter(|h|!mempool.exist(h)).collect();
                    drop(mempool);
                    if to_get.len() > 0 {
                        peer.write(Message::GetTransactions(to_get));
                    }
                }
                Message::GetTransactions(hashes) => {
                    //Check whether the hashes are already in mempool; if yes,sending the corresponding transactions thru Transactions.
                    debug!("GetTransactions message received: {:?}", hashes);
                    let trans = self.mempool.lock().unwrap().get_trans(&hashes);
                    if trans.len() > 0 {
                        peer.write(Message::Transactions(trans));
                    }
                }
                Message::Transactions(trans) => {
                    //Add the transactions into mempool if not already in it and passing signature check
                    debug!("Transactions message received!!");
                    let mut mempool = self.mempool.lock().unwrap();
                    let mut new_hashes = Vec::<H256>::new();
                    for t in trans.iter() {
                        if mempool.add_with_check(t) {
                            new_hashes.push(t.hash());
                        }
                    }
                    drop(mempool);
                    if new_hashes.len() > 0  && !self.supernode {
                        self.server.broadcast(Message::NewTransactionHashes(new_hashes));
                    }
                }
                Message::NewPeers(content) => {
                    //Broadcast all known address(including itself) to p2p_peers
                    debug!("Server {:?} receive address{:?}!!", self.self_addr, content);
                    let mut peers_info = self.peers_info.lock().unwrap();
                    let mut new_peers = Vec::<(H160, Box<[u8; ED25519_PUBLIC_KEY_LEN]>, u16)>::new();
                    for info in content.iter() {
                        let addr = info.0.clone();
                        let pub_key = info.1.clone();
                        let port = info.2;
                        if addr != self.self_addr && !peers_info.contains(&addr) {
                            peers_info.insert(&addr, pub_key, port);
                            new_peers.push(info.clone());
                        }
                    }
                    if new_peers.len() > 0 {
                        self.server.broadcast(Message::NewPeers(new_peers));
                    }
                }
                Message::Introduce(content) => {
                    /* Welcome new peer joining:
                       Add new-coming address to peer_addrs & send back all known address(including itself) & broadcast new address to p2p_peers
                       Sync longest chain to new peer
                    */
                    let addr = content.0;
                    let pub_key = content.1.clone();
                    let port = content.2;
                    debug!("Server {:?} receive IntroduceAddr {:?}!!", self.self_addr, addr);
                    let blockchain = self.blockchain.lock().unwrap();
                    let mut peers_info = self.peers_info.lock().unwrap();

                    if !peers_info.contains(&addr) {
                        peers_info.insert(&addr, pub_key, port);
                        let mut all_peers_info = peers_info.get_all_peers_info();
                        // Also include self_address
                        all_peers_info.push((self.self_addr, self.self_pub_key.clone(), self.self_port));
                        peer.write(Message::NewPeers(all_peers_info));

                        self.server.broadcast(Message::NewPeers(vec![content]));
                    }

                    peer.write(Message::NewBlockHashes(blockchain.hash_chain()));
                }
            }
        }
    }
}
