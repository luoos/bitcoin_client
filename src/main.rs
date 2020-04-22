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

use crate::blockchain::Blockchain;
use crate::mempool::MemPool;
use crate::account::Account;
use crate::peers::Peers;
use crate::network::message::Message;
use crate::crypto::key_pair;
use ring::signature::KeyPair;

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
    )
    .get_matches();

    // init logger
    let verbosity = matches.occurrences_of("verbose") as usize;
    stderrlog::new().verbosity(verbosity).init().unwrap();

    // parse p2p server address
    let p2p_addr = matches
        .value_of("peer_addr")
        .unwrap()
        .parse::<net::SocketAddr>()
        .unwrap_or_else(|e| {
            error!("Error parsing P2P server address: {}", e);
            process::exit(1);
        });

    // parse api server address
    let api_addr = matches
        .value_of("api_addr")
        .unwrap()
        .parse::<net::SocketAddr>()
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
    let key_pair = Arc::new(key_pair::random());
    let account = Arc::new(Account::new(&key_pair));
    let addr = account.addr;
    info!("Client get started: address is {:?}, {:?}", addr, &key_pair.public_key());

    // create peer(for transaction)
    let peers = Arc::new(Mutex::new(Peers::new()));

    // create blockchain
    let blockchain = Arc::new(Mutex::new(Blockchain::new()));

    // create mempool
    let mempool = Arc::new(Mutex::new(MemPool::new()));

    // start the transaction_generator
    let transaction_generator_ctx = transaction_generator::new(
        &server,
        &mempool,
        &blockchain,
        &peers,
        &account,
    );
    transaction_generator_ctx.start();

    // start server worker
    let worker_ctx = worker::new(
        p2p_workers,
        msg_rx,
        &server,
        &blockchain,
        &mempool,
        &peers,
        account.addr,
    );
    worker_ctx.start();

    // start the miner
    let (miner_ctx, miner) = miner::new(
        &server,
        &blockchain,
        &mempool,
        &key_pair,
    );
    miner_ctx.start();

    // connect to known peers
    if let Some(known_peers) = matches.values_of("known_peer") {
        let known_peers: Vec<String> = known_peers.map(|x| x.to_owned()).collect();
        let server = server.clone();
        thread::spawn(move || {
            for peer in known_peers {
                loop {
                    let addr = match peer.parse::<net::SocketAddr>() {
                        Ok(x) => x,
                        Err(e) => {
                            error!("Error parsing peer address {}: {}", &peer, e);
                            break;
                        }
                    };
                    match server.connect(addr) {
                        Ok(_) => {
                            info!("Connected to outgoing peer {}", &addr);
                            break;
                        }
                        Err(e) => {
                            error!(
                                "Error connecting to peer {}, retrying in one second: {}",
                                addr, e
                            );
                            thread::sleep(time::Duration::from_millis(1000));
                            continue;
                        }
                    }
                }
            }
        });
    }

    thread::sleep(time::Duration::from_millis(500));
    // introduce myself to network_peers
    server.broadcast(Message::Introduce(addr));

    // start the API server
    ApiServer::start(
        api_addr,
        &miner,
        &server,
        &blockchain,
        &mempool,
    );

    loop {
        std::thread::park();
    }
}