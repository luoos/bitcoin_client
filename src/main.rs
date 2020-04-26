#[cfg(test)]
#[macro_use]
extern crate hex_literal;

#[macro_use]
extern crate lazy_static;

pub mod account;
pub mod api;
pub mod block;
pub mod blockchain;
pub mod crypto;
pub mod miner;
pub mod network;
pub mod transaction;
pub mod config;
pub mod helper;
pub mod mempool;
pub mod transaction_generator;
pub mod peers;
#[allow(unused_variables)] // TODO: remove
#[allow(dead_code)] // TODO: remove
pub mod spread;

use clap::clap_app;
use crossbeam::channel;
use log::{error, info};
use api::Server as ApiServer;
use network::{server, worker};
use std::net;
use std::process;
use std::thread;
use std::sync::{Arc, Mutex};
use std::time;
use clap::ArgMatches;
use net::SocketAddr;

use crate::blockchain::Blockchain;
use crate::mempool::MemPool;
use crate::account::Account;
use crate::peers::Peers;
use crate::network::message::Message;
use crate::crypto::key_pair;
use ring::signature::KeyPair;

fn run_regular_server(matches: ArgMatches) {
    // parse p2p server address
    let p2p_addr = matches
        .value_of("peer_addr")
        .unwrap()
        .parse::<SocketAddr>()
        .unwrap_or_else(|e| {
            error!("Error parsing P2P server address: {}", e);
            process::exit(1);
        });

    // parse api server address
    let api_addr = matches
        .value_of("api_addr")
        .unwrap()
        .parse::<SocketAddr>()
        .unwrap_or_else(|e| {
            error!("Error parsing API server address: {}", e);
            process::exit(1);
        });

    // create channels between server and worker
    let (msg_tx, msg_rx) = channel::unbounded();

    let (spreader, spreader_ctx) = spread::get_spreader(config::SPREADER);
    spreader_ctx.start();
    // start the p2p server
    let (server_ctx, server) = server::new(p2p_addr, msg_tx, spreader).unwrap();
    server_ctx.start().unwrap();

    // start the worker
    let p2p_workers = matches
        .value_of("p2p_workers")
        .unwrap()
        .parse::<usize>()
        .unwrap_or_else(|e| {
            error!("Error parsing P2P workers: {}", e);
            process::exit(1);
        });

    // create user account
    let port = p2p_addr.port();
    let key_pair = Arc::new(key_pair::random());
    let account  = Arc::new(Account::new(port, key_pair.clone()));
    let addr = account.addr;
    let pub_key = account.get_pub_key();
    info!("Client get started: address is {:?}, {:?}", addr, &key_pair.public_key());

    // create peer(for transaction)
    let peers = Arc::new(Mutex::new(Peers::new()));

    // create blockchain
    let blockchain = Arc::new(Mutex::new(Blockchain::new()));

    // create mempool
    let mempool = Arc::new(Mutex::new(MemPool::new()));

    // start the transaction_generator
    let transaction_generator_ctx = transaction_generator::new(
        server.clone(),
        mempool.clone(),
        blockchain.clone(),
        peers.clone(),
        account.clone(),
    );
    transaction_generator_ctx.start();

    // start server worker
    let worker_ctx = worker::new(
        p2p_workers,
        msg_rx,
        server.clone(),
        blockchain.clone(),
        mempool.clone(),
        peers.clone(),
        account.addr,
        pub_key.clone(),
        port
    );
    worker_ctx.start();

    // start the miner
    let (miner_ctx, miner) = miner::new(
        server.clone(),
        blockchain.clone(),
        mempool.clone(),
        key_pair.clone(),
    );
    miner_ctx.start();

    // connect to known peers
    if let Some(known_peers) = matches.values_of("known_peer") {
        let known_peers: Vec<SocketAddr> = known_peers.map(|x| x.parse::<SocketAddr>().unwrap()).collect();
        helper::connect_peers(&server, &known_peers);
    }

    thread::sleep(time::Duration::from_millis(200));
    // introduce myself to network_peers
    server.broadcast(Message::Introduce((addr, pub_key, port)));

    // start the API server
    ApiServer::start(
        api_addr,
        miner.clone(),
        blockchain.clone(),
        mempool.clone(),
        peers.clone(),
    );

    loop {
        std::thread::park();
    }
}

fn run_supernode(matches: ArgMatches) {

    let probe_cnt = matches
        .value_of("probe")
        .unwrap()
        .parse::<usize>()
        .unwrap_or_else(|e| {
            error!("Error parsing probe: {}", e);
            process::exit(1);
        });

    let node_socket_addr = matches
        .value_of("peer_addr")
        .unwrap()
        .parse::<SocketAddr>()
        .unwrap_or_else(|e| {
            error!("Error parsing API server address: {}", e);
            process::exit(1);
        });

    let api_addr = matches
        .value_of("api_addr")
        .unwrap()
        .parse::<SocketAddr>()
        .unwrap_or_else(|e| {
            error!("Error parsing API server address: {}", e);
            process::exit(1);
        });

    let known_peers = matches.values_of("known_peer").unwrap();
    let known_peers: Vec<SocketAddr> = known_peers.map(|x| x.parse::<SocketAddr>().unwrap()).collect();

    let mut nodes_addr = vec![node_socket_addr];

    for i in 1..probe_cnt {
        let mut new_node = nodes_addr[0].clone();
        new_node.set_port(nodes_addr[0].port() + i as u16);
        nodes_addr.push(new_node);
    }

    let peers = Arc::new(Mutex::new(Peers::new()));
    let blockchain = Arc::new(Mutex::new(Blockchain::new()));
    let mempool = Arc::new(Mutex::new(MemPool::new()));

    for addr in nodes_addr.iter() {
        let (msg_tx, msg_rx) = channel::unbounded();

        let key_pair = Arc::new(key_pair::random());
        let account  = Arc::new(Account::new(addr.port(), key_pair.clone()));
        let pub_key = account.get_pub_key();

        let (spreader, _) = spread::get_spreader(spread::Spreader::Default);
        let (server_ctx, server) = server::new(addr.clone(), msg_tx, spreader).unwrap();
        server_ctx.start().unwrap();

        let mut worker_ctx = worker::new(
            1,
            msg_rx,
            server.clone(),
            blockchain.clone(),
            mempool.clone(),
            peers.clone(),
            account.addr,
            pub_key.clone(),
            addr.port()
        );
        worker_ctx.as_supernode();
        worker_ctx.start();

        helper::connect_peers(&server, &known_peers);
        server.broadcast(Message::Introduce((account.addr, pub_key, addr.port())));
    }

    let (msg_tx, _) = channel::unbounded();
    let (spreader, _) = spread::get_spreader(spread::Spreader::Default);
    let (_, server) = server::new(nodes_addr[0], msg_tx, spreader).unwrap();  // Fake
    let key_pair = Arc::new(key_pair::random()); // Fake

    let (_, miner) = miner::new(  // Fake
        server.clone(),
        blockchain.clone(),
        mempool.clone(),
        key_pair.clone(),
    );

    ApiServer::start(
        api_addr,
        miner.clone(),  // Fake
        blockchain.clone(),  // Fake
        mempool.clone(),
        peers.clone(),
    );

    loop {
        std::thread::park();
    }
}

fn main() {
    // parse command line arguments
    let matches = clap_app!(Bitcoin =>
     (version: "0.1")
     (about: "Bitcoin client")
     (@arg verbose: -v ... "Increases the verbosity of logging")
     (@arg peer_addr: --p2p [ADDR] default_value("127.0.0.1:6000") "Sets the IP address and the port of the P2P server")
     (@arg api_addr: --api [ADDR] default_value("127.0.0.1:7000") "Sets the IP address and the port of the API server")
     (@arg known_peer: -c --connect ... [PEER] "Sets the peers to connect to at start")
     (@arg p2p_workers: --("p2p-workers") [INT] default_value("4") "Sets the number of worker threads for P2P server")
     (@arg supernode: --supernode "Run as a super node")
     (@arg probe: -p --probe [INT] default_value("2") "Number of connect to each regular server for supernode")
    )
    .get_matches();

    let verbosity = matches.occurrences_of("verbose") as usize;
    stderrlog::new().verbosity(verbosity).init().unwrap();

    if matches.is_present("supernode") {
        run_supernode(matches);
    } else {
        run_regular_server(matches);
    }
}