use crate::transaction::*;
use crate::blockchain::Blockchain;
use crate::block::*;
use crate::crypto::hash::{H256, H160};
use crate::crypto::key_pair;
use crate::config::{RAND_INPUTS_NUM, RAND_OUTPUTS_NUM, COINBASE_REWARD, EASIEST_DIF};
use crate::miner;
use crate::mempool::MemPool;
use crate::transaction_generator;
use crate::network::{worker, server};
use crate::account::Account;
use crate::peers::Peers;

use log::{info, error};
use rand::{Rng,thread_rng};
use rand::distributions::Distribution;
use ring::signature::{KeyPair, Ed25519KeyPair};
use ring::digest;
use std::sync::{Arc, Mutex};
use std::net::SocketAddr;
use crossbeam::channel;

///Network
pub fn new_server_env(ipv4_addr: SocketAddr) -> (server::Handle, miner::Context, transaction_generator::Context, Arc<Mutex<Blockchain>>, Arc<Mutex<MemPool>>, Arc<Mutex<Peers>>, H160) {
    let (sender, receiver) = channel::unbounded();
    let (server_ctx, server) = server::new(ipv4_addr, sender).unwrap();
    server_ctx.start().unwrap();

    let key_pair = key_pair::random();
    let account = Account::new(key_pair);
    let addr = account.addr;

    let peers = Arc::new(Mutex::new(Peers::new()));

    let mut blockchain = Blockchain::new();
    let difficulty: H256 = gen_difficulty_array(EASIEST_DIF).into();
    blockchain.change_difficulty(&difficulty);
    let blockchain =  Arc::new(Mutex::new(blockchain));

    let mempool = MemPool::new();
    let mempool = Arc::new(Mutex::new(mempool));

    let worker_ctx = worker::new(4, receiver, &server, &blockchain, &mempool, &peers, addr);
    worker_ctx.start();

    let (miner_ctx, _miner) = miner::new(&server, &blockchain, &mempool);

    let transaction_generator_ctx =
        transaction_generator::new(&server, &mempool, &blockchain, &State::new(), &peers, account.key_pair, addr);

    (server, miner_ctx, transaction_generator_ctx, blockchain, mempool, peers, account.addr)
}

pub fn connect_peers(server: &server::Handle, known_peers: Vec<SocketAddr>) {
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

///Block
pub fn generate_mined_block(parent_hash: &H256, difficulty: &H256) -> Block {
    let content = generate_random_content();
    let mut header = generate_header(parent_hash, &content, 0, difficulty);
    // assume a easy difficulty
    assert!(miner::mining_base(&mut header, difficulty.clone()));
    Block::new(header, content)
}

pub fn generate_random_block(parent: &H256) -> Block {
    let content = generate_random_content();
    let header = generate_random_header(parent, &content);
    Block::new(header, content)
}

pub fn generate_random_header(parent: &H256, content: &Content) -> Header {
    let mut rng = rand::thread_rng();
    let nonce: u32 = rng.gen();
    let timestamp: u128 = rng.gen();
    let difficulty = generate_random_hash();
    let merkle_root = content.merkle_root();
    Header::new(
        parent, nonce, timestamp,
        &difficulty, &merkle_root
    )
}

pub fn generate_random_content() -> Content {
    let mut content = Content::new();
    let mut rng = rand::thread_rng();
    let size: u32 = rng.gen_range(10, 20);
    for _ in 0..size {
        content.add_tran(generate_random_signed_transaction());
    }
    content
}

pub fn generate_block(parent: &H256, nonce: u32, difficulty: &H256)
                      -> Block {
    let content = generate_content();
    let header = generate_header(parent, &content, nonce, difficulty);
    Block::new(header, content)
}

pub fn generate_header(parent: &H256, content: &Content, nonce: u32,
                   difficulty: &H256) -> Header {
    let ts = 100u128;
    let merkle_root = content.merkle_root();
    Header::new(
        parent, nonce, ts,
        difficulty, &merkle_root,
    )
}

fn generate_content() -> Content {
    let mut content = Content::new();
    let tran = generate_random_signed_transaction();
    content.add_tran(tran);
    content
}

/// Transaction
pub fn generate_signed_transaction(key: &Ed25519KeyPair,
        inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> SignedTransaction {
    let pub_key_bytes: Box<[u8]> = key.public_key().as_ref().into();
    let tran = Transaction::new(inputs, outputs);
    let signature = sign(&tran, &key);
    let sig_bytes: Box<[u8]> = signature.as_ref().into();
    return SignedTransaction::new(tran, sig_bytes, pub_key_bytes);
}

pub fn generate_signed_coinbase_transaction(key: &Ed25519KeyPair) -> SignedTransaction {
    let addr: H160 = digest::digest(&digest::SHA256, key.public_key().as_ref()).into();
    let txoutput = TxOutput {rec_address: addr.clone(), val: COINBASE_REWARD};
    return generate_signed_transaction(key, Vec::new(), vec![txoutput]);
}

pub fn generate_random_signed_transaction_from_keypair(key: &Ed25519KeyPair) -> SignedTransaction {
    let transaction = generate_random_transaction();
    let public_key: Box<[u8]> = key.public_key().as_ref().into();
    let signature: Box<[u8]> = sign(&transaction, &key).as_ref().into();
    SignedTransaction::new(transaction, signature, public_key)
}

pub fn generate_random_signed_transaction() -> SignedTransaction {
    let transaction = generate_random_transaction();
    let key = key_pair::random();
    let public_key: Box<[u8]> = key.public_key().as_ref().into();
    let signature: Box<[u8]> = sign(&transaction, &key).as_ref().into();
    SignedTransaction::new(transaction, signature, public_key)
}

pub fn generate_random_transaction() -> Transaction {
    let mut inputs = Vec::<TxInput>::new();
    let mut outputs = Vec::<TxOutput>::new();
    for _ in 0..RAND_INPUTS_NUM {
        inputs.push(generate_random_txinput());
    }
    for _ in 0..RAND_OUTPUTS_NUM {
        outputs.push(generate_random_txoutput());
    }
    Transaction::new(inputs, outputs)
}

pub fn generate_random_txinput() -> TxInput {
    let pre_hash = generate_random_hash();
    let mut rng = rand::thread_rng();
    let index: u32 = rng.gen_range(0, 10);
    TxInput {pre_hash, index}
}

pub fn generate_random_txoutput() -> TxOutput {
    let rec_address = generate_random_h160();
    let mut rng = rand::thread_rng();
    let val: u64 = rng.gen_range(0, 256);
    TxOutput {rec_address, val}
}

/// Hash
pub fn generate_random_hash() -> H256 {
    let mut rng = rand::thread_rng();
    let random_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    let mut raw_bytes = [0; 32];
    raw_bytes.copy_from_slice(&random_bytes);
    (&raw_bytes).into()
}

pub fn generate_random_h160() -> H160 {
    let mut rng = rand::thread_rng();
    let random_bytes: Vec<u8> = (0..20).map(|_| rng.gen()).collect();
    let mut raw_bytes = [0; 20];
    raw_bytes.copy_from_slice(&random_bytes);
    (&raw_bytes).into()
}

///Other
// Generate 32-bytes array to set difficulty
pub fn gen_difficulty_array(mut zero_cnt: i32) -> [u8; 32] {
    let mut difficulty : [u8; 32] = [std::u8::MAX; 32];

    for i in 0..32 {
        if zero_cnt <= 0 {break}

        if zero_cnt < 8 {
            difficulty[i] = 0xffu8 >> zero_cnt;
        } else {
            difficulty[i] = 0u8;
        }
        zero_cnt -= 8;
    }
    difficulty
}

#[allow(dead_code)]
pub fn generate_random_str() -> String {
    let rng = thread_rng();
    rand::distributions::Alphanumeric.sample_iter(rng).take(10).collect()
}