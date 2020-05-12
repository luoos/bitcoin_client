use serde::Serialize;
use crate::miner::Handle as MinerHandle;
use crate::blockchain::Blockchain;
use crate::block::{PrintableBlock, PrintableContent, PrintableState};
use crate::mempool::MemPool;
use crate::transaction::{PrintableTransaction, SignedTransaction};
use crate::transaction_generator::Handle as TxGeneratorHandle;
use crate::peers::Peers;
use crate::network::estimator::{start_first_timestamp_estimate};

use log::info;
use std::collections::HashMap;
use std::thread;
use tiny_http::Header;
use tiny_http::Response;
use tiny_http::Server as HTTPServer;
use url::Url;
use tera::{Tera, Context};
use std::sync::{Arc, Mutex};


pub struct Server {
    handle: HTTPServer,
    miner: MinerHandle,
    transaction_generator: TxGeneratorHandle,
    blockchain: Arc<Mutex<Blockchain>>,
    mempool: Arc<Mutex<MemPool>>,
    peers : Arc<Mutex<Peers>>,
}

#[derive(Serialize)]
struct ApiResponse {
    success: bool,
    message: String,
}

#[derive(Serialize)]
struct EstimatorRes {
    success: bool,
    recall: f64,
    precision: f64,
    mempool_size: usize,
}

macro_rules! respond_json {
    ($req:expr, $success:expr, $message:expr ) => {{
        let content_type = "Content-Type: application/json".parse::<Header>().unwrap();
        let payload = ApiResponse {
            success: $success,
            message: $message.to_string(),
        };
        let resp = Response::from_string(serde_json::to_string_pretty(&payload).unwrap())
            .with_header(content_type);
        $req.respond(resp).unwrap();
    }};
}

macro_rules! check_estimator {
    ($req:expr, $success:expr, $precision:expr, $recall:expr, $mempool_size:expr) => {{
        let content_type = "Content-Type: application/json".parse::<Header>().unwrap();
        let payload = EstimatorRes {
            success: $success,
            recall: $recall,
            precision: $precision,
            mempool_size: $mempool_size,
        };
        let resp = Response::from_string(serde_json::to_string_pretty(&payload).unwrap())
            .with_header(content_type);
        $req.respond(resp).unwrap();
    }};
}

lazy_static! {
    pub static ref TEMPLATES: Tera = {
        let mut tera = match Tera::new("src/api/templates/**/*") {
            Ok(t) => t,
            Err(e) => {
                println!("Parsing error(s): {}", e);
                ::std::process::exit(1);
            }
        };
        tera.autoescape_on(vec!["html", ".sql"]);
        // tera.register_filter("do_nothing", do_nothing_filter);
        tera
    };
}

impl Server {
    pub fn start(
        addr: std::net::SocketAddr,
        miner: MinerHandle,
        transaction_generator: TxGeneratorHandle,
        blockchain: Arc<Mutex<Blockchain>>,
        mempool: Arc<Mutex<MemPool>>,
        peers : Arc<Mutex<Peers>>,
    ) {
        let handle = HTTPServer::http(&addr).unwrap();
        let server = Self {
            handle,
            miner,
            transaction_generator,
            blockchain,
            mempool,
            peers,
        };
        thread::spawn(move || {
            for req in server.handle.incoming_requests() {
                let miner = server.miner.clone();
                let transaction_generator = server.transaction_generator.clone();
                let blockchain = Arc::clone(&server.blockchain);
                let mempool = Arc::clone(&server.mempool);
                let peers = server.peers.clone();
                thread::spawn(move || {
                    // a valid url requires a base
                    let base_url = Url::parse(&format!("http://{}/", &addr)).unwrap();
                    let url = match base_url.join(req.url()) {
                        Ok(u) => u,
                        Err(e) => {
                            respond_json!(req, false, format!("error parsing url: {}", e));
                            return;
                        }
                    };
                    match url.path() {
                        "/miner/start" => {
                            let params = url.query_pairs();
                            let params: HashMap<_, _> = params.into_owned().collect();
                            let lambda = match params.get("lambda") {
                                Some(v) => v,
                                None => {
                                    respond_json!(req, false, "missing lambda");
                                    return;
                                }
                            };
                            let lambda = match lambda.parse::<u64>() {
                                Ok(v) => v,
                                Err(e) => {
                                    respond_json!(
                                        req,
                                        false,
                                        format!("error parsing lambda: {}", e)
                                    );
                                    return;
                                }
                            };
                            miner.start(lambda);
                            respond_json!(req, true, "ok");
                        }
                        "/miner/stop" => {
                            miner.stop();
                            respond_json!(req, true, "ok");
                        }
                        "/miner/pause" => {
                            miner.pause();
                            respond_json!(req, true, "ok");
                        }
                        "/blockchain/showheader" => {
                            let blocks = blockchain.lock().unwrap().block_chain();
                            let pblock = PrintableBlock::from_block_vec(&blocks);
                            let mut context = Context::new();
                            context.insert("blocks", &pblock);

                            let content_type = "Content-Type: text/html".parse::<Header>().unwrap();
                            let html = TEMPLATES.render("header.html", &context).unwrap();
                            let resp = Response::from_string(html)
                                .with_header(content_type);
                            req.respond(resp).unwrap();
                        }
                        "/blockchain/showtx" => {
                            let contents = blockchain.lock().unwrap().content_chain();
                            let pcontent = PrintableContent::from_content_vec(&contents);
                            let mut context = Context::new();
                            context.insert("contents", &pcontent);

                            let content_type = "Content-Type: text/html".parse::<Header>().unwrap();
                            let html = TEMPLATES.render("tx.html", &context).unwrap();
                            let resp = Response::from_string(html)
                                .with_header(content_type);
                            req.respond(resp).unwrap();
                        }
                        "/blockchain/showstate" => {
                            let cur_state = blockchain.lock().unwrap().tip_block_state();
                            let pstate = PrintableState::from_state(&cur_state);
                            let mut context = Context::new();
                            context.insert("state", &pstate);

                            let content_type = "Content-Type: text/html".parse::<Header>().unwrap();
                            let html = TEMPLATES.render("state.html", &context).unwrap();
                            let resp = Response::from_string(html)
                                .with_header(content_type);
                            req.respond(resp).unwrap();
                        }
                        "/mempool/showtx" => {
                            let trans_map = &mempool.lock().unwrap().transactions;
                            let trans: Vec<SignedTransaction> = trans_map.values().cloned().collect();
                            let ptrans = PrintableTransaction::from_signedtx_vec(&trans);
                            let mut context = Context::new();
                            context.insert("txs", &ptrans);
                            context.insert("size", &ptrans.len());

                            let content_type = "Content-Type: text/html".parse::<Header>().unwrap();
                            let html = TEMPLATES.render("mempool.html", &context).unwrap();
                            let resp = Response::from_string(html)
                                .with_header(content_type);
                            req.respond(resp).unwrap();
                        }
                        "/txgenerator/stop" => {
                            transaction_generator.stop();
                            respond_json!(req, true, "ok");
                        }
                        "/txgenerator/pause" => {
                            transaction_generator.pause();
                            respond_json!(req, true, "ok");
                        }
                        "/estimator/ft" => {
                            let params = url.query_pairs();
                            let params: HashMap<_, _> = params.into_owned().collect();
                            let n = match params.get("n") {
                                Some(v) => v,
                                None => {
                                    respond_json!(req, false, "missing lambda");
                                    return;
                                }
                            };
                            let n = match n.parse::<u64>() {
                                Ok(v) => v,
                                Err(e) => {
                                    respond_json!(
                                        req,
                                        false,
                                        format!("error parsing lambda: {}", e)
                                    );
                                    return;
                                }
                            };
                            let mem = mempool.lock().unwrap();
                            let mem_size = mem.size();
                            let peer_info = peers.lock().unwrap();
                            let res = start_first_timestamp_estimate(&mem.transactions, &mem.ts_addr_map, &peer_info.info_map, n);
//                            let correct_count = check_right_count(&res, &peer_info.info_map);

                            check_estimator!(req, true, res.0, res.1, mem_size);
                        }
                        _ => {
                            let content_type =
                                "Content-Type: application/json".parse::<Header>().unwrap();
                            let payload = ApiResponse {
                                success: false,
                                message: "endpoint not found".to_string(),
                            };
                            let resp = Response::from_string(
                                serde_json::to_string_pretty(&payload).unwrap(),
                            )
                                .with_header(content_type)
                                .with_status_code(404);
                            req.respond(resp).unwrap();
                        }
                    }
                });
            }
        });
        info!("API server listening at {}", &addr);
    }
}
