use crate::transaction::*;
use crate::blockchain::Blockchain;
use crate::block::*;
use crate::crypto::hash::{H256, H160};
use crate::crypto::key_pair;
use crate::config::*;
use crate::miner;
use crate::mempool::MemPool;
use crate::transaction_generator;
use crate::network::{worker, server};
use crate::account::Account;
use crate::peers::Peers;
use crate::spread::{self, Spreader};

use log::{info, error};
use rand::{Rng,thread_rng};
use rand::distributions::Distribution;
use rand::seq::SliceRandom;
use ring::signature::{KeyPair, Ed25519KeyPair};
use ring::digest;
use std::sync::{Arc, Mutex};
use chrono::prelude::*;
use std::net::SocketAddr;
use crossbeam::channel;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

///Network
pub fn new_server_env(ipv4_addr: SocketAddr, spreader_type : Spreader, is_supernode: bool) -> (server::Handle, miner::Context, transaction_generator::Context,
                                                Arc<Mutex<Blockchain>>, Arc<Mutex<MemPool>>, Arc<Mutex<Peers>>,
                                                Arc<Account>) {
    let (sender, receiver) = channel::unbounded();

    let peers = Arc::new(Mutex::new(Peers::new()));

    let mut blockchain = Blockchain::new();
    let difficulty: H256 = gen_difficulty_array(EASIEST_DIF).into();
    blockchain.change_difficulty(&difficulty);
    let blockchain =  Arc::new(Mutex::new(blockchain));

    let mempool = Arc::new(Mutex::new(MemPool::new()));

    let using_dandelion =  spreader_type == Spreader::Dandelion || spreader_type == Spreader::DandelionPlus;

    let (spreader, spreader_ctx) = spread::get_spreader(spreader_type, mempool.clone());
    spreader_ctx.start();
    let (server_ctx, server) = server::new(ipv4_addr, sender, spreader).unwrap();
    server_ctx.start().unwrap();

    let key_pair = Arc::new(key_pair::random());
    let account = Arc::new(Account::new(ipv4_addr.port(),key_pair.clone()));
    let addr = account.addr;
    let pub_key = account.get_pub_key();
    let port = account.port;

    let mut worker_ctx = worker::new(4, receiver, server.clone(),
        blockchain.clone(), mempool.clone(), peers.clone(), addr, pub_key, port);
    if is_supernode {
        worker_ctx.as_supernode();
    }
    worker_ctx.start();

    let (miner_ctx, _miner) = miner::new(server.clone(),
        blockchain.clone(), mempool.clone(), key_pair.clone());

    let transaction_generator_ctx =
        transaction_generator::new(server.clone(),
            mempool.clone(), blockchain.clone(), peers.clone(), account.clone(), using_dandelion);

    (server, miner_ctx, transaction_generator_ctx, blockchain, mempool, peers, account)
}

pub fn connect_peers(server: &server::Handle, known_peers: &Vec<SocketAddr>) {
    for peer_addr in known_peers {
        match server.connect(*peer_addr) {
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

// Create valid transactions under current state (For now: Send to one peer & myself)
pub fn generate_valid_tran(state: &State, account: &Account, rec_addr: &H160) -> Option<SignedTransaction> {
    let (coins, balance) = state.coins_of(&account.addr);
    if balance > 0 {
        let transfer_val = gen_random_num(1, balance);
        let mut acc = 0u64;
        let mut tx_inputs = Vec::<TxInput>::new();
        for (input, val) in coins.iter() {
            tx_inputs.push(input.clone());
            acc += val;
            if acc >= transfer_val {
                break;
            }
        }
        let mut tx_outputs = Vec::<TxOutput>::new();
        tx_outputs.push(TxOutput::new(rec_addr.clone(), transfer_val));
        if acc > transfer_val {
            tx_outputs.push(TxOutput::new(account.addr.clone(), acc-transfer_val));
        }
        let new_tran = generate_signed_transaction(&account.key_pair, tx_inputs, tx_outputs);
        return Some(new_tran);
    }
    return None;
}

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

//State
pub fn generate_random_state(inputs: Vec<(H256, u32)>, outputs: Vec<(u64, H160)>) -> State {
    assert_eq!(inputs.len(), outputs.len());
    let mut state = State::new();
    for idx in 0..inputs.len() {
        state.insert(inputs[idx], outputs[idx]);
    }
    state
}

///Dandelion
pub fn get_k_random_peers(peer_list: &Vec<SocketAddr>, k: usize) -> Vec<SocketAddr> {
    if peer_list.is_empty() {
        return peer_list.to_owned()
    }

    let mut selected_peer_list: Vec<SocketAddr> = Vec::new();
    let mut selected_idx: HashSet<u64> = HashSet::new();

    while selected_peer_list.len() < k {
        let rand_idx = gen_random_num(0, peer_list.len() as u64 - 1);
        if !selected_idx.contains(&rand_idx) {
            selected_idx.insert(rand_idx);
            selected_peer_list.push(peer_list[rand_idx as usize]);
        }
    }
    selected_peer_list
}

pub fn get_k_random_peers_from_idx(peer_list: &Vec<usize>, k: usize) -> Vec<usize> {
    if peer_list.is_empty() {
        return peer_list.to_owned()
    }

    let mut selected_peer_list: Vec<usize> = Vec::new();
    let mut selected_idx: HashSet<u64> = HashSet::new();
    let peer_num: u64 = peer_list.len() as u64;

    while selected_peer_list.len() < k {
        let rand_idx = gen_random_num(0, peer_num - 1);
        if !selected_idx.contains(&rand_idx) {
            selected_idx.insert(rand_idx);
            selected_peer_list.push(rand_idx as usize);
        }
    }
    selected_peer_list
}

// Select destination for inbound_addr (prevent cycle)
pub fn select_destination(mut destinations: Vec<SocketAddr>, inbound_addr: SocketAddr) -> SocketAddr {
    destinations.retain(|&x| x != inbound_addr);
    let candidate_num = destinations.len() as u64;
    if destinations.is_empty() {
        //Todo: route back?
        return inbound_addr;
    }
    let rand_idx = gen_random_num(0, candidate_num - 1);
    destinations[rand_idx as usize]
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

pub fn gen_random_num(lo: u64, hi: u64) -> u64 {
    // inclusive at both ends
    let mut rng = thread_rng();
    return rng.gen_range(lo, hi+1);
}

pub fn gen_shuffled_peer_list(peer_list : &Vec<usize>) -> Vec<usize>{
    let mut peer_list_copy: Vec<usize> = peer_list.to_vec();
    let mut rng = rand::thread_rng();
    peer_list_copy.shuffle(&mut rng);
    return peer_list_copy
}

pub fn get_current_time_in_nano() -> i64{
    let now = Utc::now();
    now.timestamp_nanos()
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
        where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

pub fn load_network_structure() -> Option<HashMap<i32, Vec<i32>>> {
    if let Ok(lines) = read_lines("./network.txt") {
        let mut map: HashMap<i32, Vec<i32>> = HashMap::new();
        for line in lines {
            if let Ok(l) = line {
                let mut split_colon = l.split(":");
                let key = split_colon.next().unwrap().parse::<i32>().unwrap();
                let neighbors: Vec<i32> = split_colon.next().unwrap()
                        .split(",").map(|x| x.parse::<i32>().unwrap()).collect();
                map.insert(key, neighbors);
            }
        }
        return Some(map)
    } else {
        return None
    }
}

pub fn generate_random_str() -> String {
    let rng = thread_rng();
    rand::distributions::Alphanumeric.sample_iter(rng).take(10).collect()
}

#[cfg(any(test, test_utilities))]
pub mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::account::Account;
    use crate::crypto::key_pair;
    use crate::block::State;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_gen_valid_tran() {
        let key_pair = Arc::new(key_pair::random());
        let port = 14159;
        let account = Arc::new(Account::new(port, key_pair));
        let port2 = 26535;
        let key_pair_2 = Arc::new(key_pair::random());
        let account_2 = Arc::new(Account::new(port2, key_pair_2));

        let mut state = State::new();
        let h256_1 = generate_random_hash();
        let h256_2 = generate_random_hash();
        let h256_3 = generate_random_hash();
        let h160_1 = account.addr.clone();
        let h160_2 = generate_random_h160();
        state.insert((h256_1, 1), (3, h160_1));
        state.insert((h256_2, 5), (7, h160_2));
        state.insert((h256_3, 11), (17, h160_1));
        let tran = generate_valid_tran(&state, &account, &h160_2);
        assert!(tran.is_some());
        let tran = generate_valid_tran(&state, &account_2, &h160_2);
        assert!(!tran.is_some());

        let mut state = State::new();
        let h256_1 = generate_random_hash();
        let h256_2 = generate_random_hash();
        let h160_1 = account.addr.clone();
        let h160_2 = generate_random_h160();
        state.insert((h256_1, 1), (1, h160_1));
        state.insert((h256_2, 5), (7, h160_2));
        let tran = generate_valid_tran(&state, &account, &h160_2);
        assert!(tran.is_some());
        let tran = tran.unwrap();
        assert!(tran.transaction.inputs.len() == 1);
        assert!(tran.transaction.outputs.len() == 1);
        assert!(tran.transaction.inputs[0] == TxInput::new(h256_1.clone(), 1));
        assert!(tran.transaction.outputs[0] == TxOutput::new(h160_2.clone(), 1));
    }

    #[test]
    fn test_get_k_random_peers() {
        let base_addr = 19601;
        let mut peers: Vec<SocketAddr> = vec![];
        peers.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), base_addr));
        let mut selected_peers: Vec<SocketAddr> = get_k_random_peers(&peers, 1);
        assert_eq!(selected_peers.len(), 1);
        peers.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), base_addr + 1));
        selected_peers = get_k_random_peers(&peers, 2);
        assert_eq!(selected_peers.len(), 2);
        assert_ne!(selected_peers[0], selected_peers[1]);
        peers.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), base_addr + 2));
        selected_peers = get_k_random_peers(&peers, 2);
        assert_eq!(selected_peers.len(), 2);
        assert_ne!(selected_peers[0], selected_peers[1]);
    }

    #[test]
    fn test_select_destination() {
        let base_addr = 19651;
        let mut peers: Vec<SocketAddr> = vec![];
        for i in 0..8 {
            peers.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), base_addr + i));
        }

        let destinations = vec![peers[0], peers[1]];

        for (idx, addr) in peers.iter().enumerate() {
            let dest = select_destination(destinations.clone(), *addr);
            if idx == 0 {
                assert_eq!(dest, peers[1]);
            } else if idx == 1 {
                assert_eq!(dest, peers[0]);
            } else {
                assert!(dest == peers[0] || dest == peers[1]);
            }
        }
    }
}
