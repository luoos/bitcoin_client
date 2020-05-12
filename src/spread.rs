use crate::network::peer;
use crate::network::message::Message;
use crate::network::peer::Handle;
use crate::network::server::Handle as ServerHandle;
use crate::helper;
use crate::config::{TRICKLE_GAP_TIME, DIFFUSION_BASE_GAP_TIME, DIFFUSION_RATE,
    EPOCH_MS, PHASE_SWITCH_PROB, IS_DIFFUSER_PROB, T_BASE};

use std::thread;
use std::sync::{Mutex, Arc};
use std::sync::mpsc::{channel, Receiver};
use std::collections::HashMap;
use log::{debug, warn};
use chrono;
use timer::{MessageTimer, Guard};
use rand_distr::{Exp, Distribution};
use crate::mempool::MemPool;
use crate::crypto::hash::{H256, Hashable};

pub trait Spreading {
    fn spread(&mut self, peers: &slab::Slab<peer::Context>, peer_index: &Vec<usize>, msg: Message, src_peer_key: Option<usize>);
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Spreader {
    Default,
    Trickle,
    Diffusion,
    Dandelion,
    DandelionPlus,
}

#[derive(Clone)]
pub enum TimerTask {
    PeerWrite(i64, Handle, Message),
    DandelionResetEpoch(i64, Arc<Mutex<usize>>),
    DandelionPlusResetEpoch(i64, Arc<Mutex<HashMap<usize, usize>>>),
    DandelionPlusFailSafeCheck(i64, Vec<H256>),
}

fn new_base(mempool: Arc<Mutex<MemPool>>, handle: ServerHandle) -> (MessageTimer<TimerTask>, Arc<Mutex<HashMap<i64, Guard>>>, Context) {
    let (sender, receiver) = channel();
    let timer = MessageTimer::new(sender);
    let guard_map = Arc::new(Mutex::new(HashMap::new()));
    let context = Context { receiver, guard_map: guard_map.clone(), mempool, server: handle };

    return (timer, guard_map, context);
}

pub struct Context {
    pub receiver: Receiver<TimerTask>,
    guard_map: Arc<Mutex<HashMap<i64, Guard>>>,
    mempool: Arc<Mutex<MemPool>>,
    server: ServerHandle,
}

impl Context {
    pub fn message_loop(&mut self) {
        loop {
            match self.receiver.recv() {
                Ok(task) => {
                    match task {
                        TimerTask::PeerWrite(nano, handle, msg) => {
                            handle.write(msg);
                            self.guard_map.lock().unwrap().remove(&nano);
                        }
                        TimerTask::DandelionResetEpoch(nano, target_index) => {
                            *target_index.lock().unwrap() = usize::max_value();
                            self.guard_map.lock().unwrap().remove(&nano);
                        }
                        TimerTask::DandelionPlusResetEpoch(nano, routing_table) => {
                            routing_table.lock().unwrap().clear();
                            self.guard_map.lock().unwrap().remove(&nano);
                        }
                        TimerTask::DandelionPlusFailSafeCheck(nano, tx_hashes) => {
                            let mut mempool = self.mempool.lock().unwrap();
                            let mut new_hashes = Vec::new();
                            for hash in tx_hashes.iter() {
                                match mempool.remove_buffered_tran(hash) {
                                    Some(tran) => {
                                        if mempool.exist(&tran.hash) {
                                            // source of this transaction
                                            new_hashes.push(tran.hash());
                                        } else if mempool.add_with_check(&tran) {
                                            new_hashes.push(tran.hash());
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            drop(mempool);
                            if new_hashes.len() > 0 {
                                self.server.broadcast(Message::NewTransactionHashes(new_hashes), None);
                            }
                            self.guard_map.lock().unwrap().remove(&nano);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    pub fn start(mut self) {
        thread::Builder::new()
            .name("message_loop".to_string())
            .spawn(move || {
                self.message_loop();
            })
            .unwrap();
    }
}

struct DefaultSpreader {
    pub timer: MessageTimer<TimerTask>,
    guard_map: Arc<Mutex<HashMap<i64, Guard>>>,
}

impl Spreading for DefaultSpreader {
    fn spread(&mut self, peers: &slab::Slab<peer::Context>, peer_list: &Vec<usize>, msg: Message, src_peer_key: Option<usize>) {
        let mut map = self.guard_map.lock().unwrap();
        for peer_id in peer_list {
            let now_nano = helper::get_current_time_in_nano();
            let guard = self.timer.schedule_with_delay(chrono::Duration::milliseconds(0),
                                                       TimerTask::PeerWrite(now_nano, peers[*peer_id].handle.clone(), msg.clone()));
            map.insert(now_nano, guard);
        }
    }
}

impl DefaultSpreader {
    pub fn new(mempool: Arc<Mutex<MemPool>>, handle: ServerHandle) -> (Self, Context) {
        let (timer, guard_map, context) = new_base(mempool, handle);
        (DefaultSpreader { timer, guard_map }, context)
    }
}

struct TrickleSpreader {
    pub timer: MessageTimer<TimerTask>,
    guard_map: Arc<Mutex<HashMap<i64, Guard>>>,
}

impl TrickleSpreader {
    pub fn new(mempool: Arc<Mutex<MemPool>>, handle: ServerHandle) -> (Self, Context) {
        let (timer, guard_map, context) = new_base(mempool, handle);
        (TrickleSpreader { timer, guard_map }, context)
    }
}

impl Spreading for TrickleSpreader {
    fn spread(&mut self, peers: &slab::Slab<peer::Context>, peer_list: &Vec<usize>, msg: Message, src_peer_key: Option<usize>) {
        let shuffled_peers_list = helper::gen_shuffled_peer_list(peer_list);
        let mut map = self.guard_map.lock().unwrap();
        for (i, peer_id) in shuffled_peers_list.iter().enumerate() {
            let now_nano = helper::get_current_time_in_nano();
            let guard = self.timer.schedule_with_delay(chrono::Duration::milliseconds(TRICKLE_GAP_TIME * (i + 1) as i64),
                                                       TimerTask::PeerWrite(now_nano, peers[*peer_id].handle.clone(), msg.clone()));
            map.insert(now_nano, guard);
        }
    }
}

// Diffusion spreading method
fn diffusion(timer: &MessageTimer<TimerTask>, guard_map: &Arc<Mutex<HashMap<i64, Guard>>>, peers: &slab::Slab<peer::Context>, peer_list: &Vec<usize>, msg: Message) {
    let mut gap_time = DIFFUSION_BASE_GAP_TIME as f64;
    let mut send_time = gap_time as i64;
    let shuffled_peers_list = helper::gen_shuffled_peer_list(peer_list);
    let mut map = guard_map.lock().unwrap();
    for peer_id in shuffled_peers_list.iter() {
        let now_nano = helper::get_current_time_in_nano();
        let guard = timer.schedule_with_delay(chrono::Duration::milliseconds(send_time),
                                                   TimerTask::PeerWrite(now_nano, peers[*peer_id].handle.clone(), msg.clone()));
        gap_time *= DIFFUSION_RATE;
        send_time += gap_time as i64;
        map.insert(now_nano, guard);
    }
}

struct DiffusionSpreader {
    timer: MessageTimer<TimerTask>,
    guard_map: Arc<Mutex<HashMap<i64, Guard>>>,
}

impl DiffusionSpreader {
    pub fn new(mempool: Arc<Mutex<MemPool>>, handle: ServerHandle) -> (Self, Context) {
        let (timer, guard_map, context) = new_base(mempool, handle);
        (DiffusionSpreader { timer, guard_map }, context)
    }
}

impl Spreading for DiffusionSpreader {
    fn spread(&mut self, peers: &slab::Slab<peer::Context>, peer_list: &Vec<usize>, msg: Message, src_peer_key: Option<usize>) {
        diffusion(&self.timer, &self.guard_map, peers, peer_list, msg);
    }
}

struct DandelionSpreader {
    timer: MessageTimer<TimerTask>,
    guard_map: Arc<Mutex<HashMap<i64, Guard>>>,
    target_index: Arc<Mutex<usize>>,
    mempool: Arc<Mutex<MemPool>>,
    epoch_period_ms: i64,
    phase_switch_prob: u64,
}

impl DandelionSpreader {
    pub fn new(mempool: Arc<Mutex<MemPool>>, handle: ServerHandle) -> (Self, Context) {
        let (timer, guard_map, context) = new_base(mempool.clone(), handle);
        (DandelionSpreader {
            timer, guard_map,
            target_index: Arc::new(Mutex::new(usize::max_value())),
            mempool,
            epoch_period_ms: EPOCH_MS,
            phase_switch_prob: PHASE_SWITCH_PROB },
         context)
    }

    #[cfg(any(test))]
    fn set_epoch_period(&mut self, period: i64) {
        self.epoch_period_ms = period;
    }
}

impl Spreading for DandelionSpreader {
    fn spread(&mut self, peers: &slab::Slab<peer::Context>, peer_list: &Vec<usize>, msg: Message, src_peer_key: Option<usize>) {
        match msg.to_owned() {
            Message::NewTransactionHashes(_) => {
                diffusion(&self.timer, &self.guard_map, peers, peer_list, msg);
            }
            Message::NewDandelionTransactions(trans) => {
                let rand_num = helper::gen_random_num(0, 99);
                if rand_num < self.phase_switch_prob {
                    // Switch to diffusion phase
                    let mut new_hashes = Vec::<H256>::new();

                    // The first one switching to diffusion should add all valid transactions into mempool
                    let mut mempool = self.mempool.lock().unwrap();
                    for t in trans.iter() {
                        if mempool.exist(&t.hash()) { // source
                            new_hashes.push(t.hash());
                        } else if mempool.add_with_check(t) {
                            new_hashes.push(t.hash());
                        }
                    }
                    drop(mempool);
                    // Relay NewTransactionHashes
                    let new_msg = Message::NewTransactionHashes(new_hashes);
                    diffusion(&self.timer, &self.guard_map, peers, peer_list, new_msg);
                } else {
                    // Select new destination upon receiving new msg
                    let target_index: usize = *self.target_index.lock().unwrap();
                    if let Some(peer) = peers.get(target_index) {
                        peer.handle.write(msg);
                    } else if peer_list.len() > 0 {
                        let random_i = helper::gen_random_num(0, peer_list.len() as u64 - 1) as usize;

                        let peer_list_index = peer_list[random_i];
                        *self.target_index.lock().unwrap() = peer_list_index;
                        peers[peer_list_index].handle.write(msg);
                        let now_nano = helper::get_current_time_in_nano();
                        let guard = self.timer.schedule_with_delay(chrono::Duration::microseconds(self.epoch_period_ms),
                                                                   TimerTask::DandelionResetEpoch(now_nano, self.target_index.clone()));
                        self.guard_map.lock().unwrap().insert(now_nano, guard);
                    }
                }
            }
            _ => {
                debug!("Invalid msg type: should only spread NewTransactionHashes!!");
            }
        }
    }
}

struct DandelionPlusSpreader {
    timer: MessageTimer<TimerTask>,
    guard_map: Arc<Mutex<HashMap<i64, Guard>>>,
    routing_table: Arc<Mutex<HashMap<usize, usize>>>, // One-to-one (inbound, outbound) pairs
    is_diffuser: bool, // true -> diffuser; false -> dandelion-relayer
    mempool: Arc<Mutex<MemPool>>,
    epoch_period_ms: i64,
    is_diffuser_prob: u64,
}

impl DandelionPlusSpreader {
    pub fn new(mempool: Arc<Mutex<MemPool>>, handle: ServerHandle) -> (Self, Context) {
        let (timer, guard_map, context) = new_base(mempool.clone(), handle);
        (DandelionPlusSpreader {
            timer, guard_map,
            routing_table: Arc::new(Mutex::new(HashMap::new())),
            is_diffuser: true, // Todo: Initialize with true?
            mempool,
            epoch_period_ms: EPOCH_MS,
            is_diffuser_prob: IS_DIFFUSER_PROB },
         context)
    }

    fn try_set_table(&mut self, peer_list: &Vec<usize>) {
        // if the routing_table is empty, try to set routing table
        let mut table = self.routing_table.lock().unwrap();
        let table_len = table.len();
        if table_len == 0 && peer_list.len() >= 2 {
            helper::set_routing_table(peer_list, &mut table);
            let rand_num = helper::gen_random_num(0, 99);
            if rand_num < self.is_diffuser_prob {
                self.is_diffuser = true;
            } else {
                self.is_diffuser = false;
            }
            self.schedule_reset_table_task();
        } else if peer_list.len() < 2 {
            self.is_diffuser = true;
        }
    }

    fn schedule_reset_table_task(&self) {
        let now_nano = helper::get_current_time_in_nano();
        let guard = self.timer.schedule_with_delay(chrono::Duration::microseconds(self.epoch_period_ms),
                                                TimerTask::DandelionPlusResetEpoch(now_nano, self.routing_table.clone()));
        self.guard_map.lock().unwrap().insert(now_nano, guard);
    }

    fn schedule_fail_safe_task(&self, hashes: Vec<H256>) {
        let exp = Exp::new(1.0/T_BASE).unwrap();
        let lambda = exp.sample(&mut rand::thread_rng()) * 1000.0;
        let now_nano = helper::get_current_time_in_nano();
        let guard = self.timer.schedule_with_delay(chrono::Duration::milliseconds(lambda as i64),
                                                TimerTask::DandelionPlusFailSafeCheck(now_nano, hashes));
        self.guard_map.lock().unwrap().insert(now_nano, guard);
    }

    #[cfg(any(test))]
    fn set_epoch_period(&mut self, period: i64) {
        self.epoch_period_ms = period;
    }
}

impl Spreading for DandelionPlusSpreader {
    fn spread(&mut self, peers: &slab::Slab<peer::Context>, peer_list: &Vec<usize>, msg: Message, mut src_peer_key: Option<usize>) {
        // src_peer_key is None when this node is the source of this msg
        if peer_list.is_empty() {
            return
        }

        match msg.to_owned() {
            Message::NewTransactionHashes(hashes) => {
                let mut mempool = self.mempool.lock().unwrap();
                // Fail-Safe Mechanism: Remove trans from buffer when received diffusion
                for h in hashes.iter() {
                    mempool.remove_buffered_tran(h);
                }
                drop(mempool);
                diffusion(&self.timer, &self.guard_map, peers, peer_list, msg);
            }
            Message::NewDandelionTransactions(trans) => {
                self.try_set_table(peer_list);
                if peer_list.len() < 2 || (self.is_diffuser && src_peer_key.is_some()) {
                    // Work as diffuser in this epoch
                    let mut new_hashes = Vec::<H256>::new();

                    // Diffuser should add all valid transactions into mempool
                    let mut mempool = self.mempool.lock().unwrap();
                    for t in trans.iter() {
                        if mempool.exist(&t.hash()) {
                            new_hashes.push(t.hash());
                        } else if mempool.add_with_check(t) {
                            new_hashes.push(t.hash());
                        }
                    }
                    drop(mempool);
                    // Relay NewTransactionHashes
                    let new_msg = Message::NewTransactionHashes(new_hashes);
                    diffusion(&self.timer, &self.guard_map, peers, peer_list, new_msg);
                } else {
                    let mut mempool = self.mempool.lock().unwrap();
                    // Fail-Safe Mechanism: Insert new trans to buffer in mempool
                    let mut hashes = Vec::new();
                    for t in trans.iter() {
                        if !mempool.contains_buffered_tran(&t.hash) {
                            mempool.insert_buffer_tran(t.clone());
                            hashes.push(t.hash.clone());
                        }
                    }
                    drop(mempool);
                    if hashes.len() > 0 {
                        self.schedule_fail_safe_task(hashes);
                    }

                    if src_peer_key.is_none() {
                        let random_i = helper::gen_random_num(0, peer_list.len() as u64 - 1) as usize;
                        src_peer_key = Some(peer_list[random_i]);
                    }

                    let src_key = src_peer_key.unwrap();

                    match self.routing_table.lock().unwrap().get(&src_key) {
                        Some(outbound_peer_index) => {
                            if let Some(peer) = peers.get(*outbound_peer_index) {
                                // src == dest can't happen
                                assert_ne!(outbound_peer_index.clone(), src_peer_key.unwrap());
                                peer.handle.write(msg.to_owned());
                            }
                        }
                        None => {warn!{"No outbound peer found in routing table, src key: {}", src_key}}
                    }
                }
            }
            _ => {
                debug!("Invalid msg type: should only spread NewTransactionHashes!!");
            }
        }
    }
}

pub fn get_spreader(key: Spreader, mempool: Arc<Mutex<MemPool>>, handle: ServerHandle) -> (Box<dyn Spreading + Send>, Context) {
    match key {
        Spreader::Default => {
            let (spreader, ctx) = DefaultSpreader::new(mempool, handle);
            (Box::new(spreader), ctx)
        }
        Spreader::Trickle => {
            let (spreader, ctx) = TrickleSpreader::new(mempool, handle);
            (Box::new(spreader), ctx)
        }
        Spreader::Diffusion => {
            let (spreader, ctx) = DiffusionSpreader::new(mempool, handle);
            (Box::new(spreader), ctx)
        }
        Spreader::Dandelion => {
            let (spreader, ctx) = DandelionSpreader::new(mempool, handle);
            (Box::new(spreader), ctx)
        }
        Spreader::DandelionPlus => {
            let (spreader, ctx) = DandelionPlusSpreader::new(mempool, handle);
            (Box::new(spreader), ctx)
        }
    }
}


#[cfg(any(test, test_utilities))]
mod tests {
    use std::net::{SocketAddr, IpAddr, Ipv4Addr};
    use std::thread::sleep;
    use std::time;
    use slab;

    use crate::helper::*;
    use super::*;
    use crate::network::peer;
    use crate::network::message::Message;
    use crate::network::server;

    fn check_mempools_total_size(mempool_list: &Vec<Arc<Mutex<MemPool>>>, expect_size: usize) {
        let mut cur = 0;
        for m in mempool_list.iter() {
            cur += m.lock().unwrap().size();
        }
        assert_eq!(expect_size, cur);
    }

    #[test]
    fn test_trickle_transaction_relay() {
        let p2p_addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 18031);
        let p2p_addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 18032);
        let p2p_addr_3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 18033);

        let (_server_1, _miner_ctx_1, mut generator_1, _blockchain_1, mempool_1, _, _) = new_server_env(p2p_addr_1, Spreader::Trickle, false);
        let (server_2, _miner_ctx_2, generator_2, _blockchain_2, mempool_2, _, _) = new_server_env(p2p_addr_2, Spreader::Trickle, false);
        let (server_3, _miner_ctx_3, generator_3, _blockchain_3, mempool_3, _, _) = new_server_env(p2p_addr_3, Spreader::Trickle, false);

        let peers_1 = vec![p2p_addr_1];
        connect_peers(&server_2, &peers_1);
        let peers_2 = vec![p2p_addr_2];
        connect_peers(&server_3, &peers_2);

        generator_1.generating();
        sleep(time::Duration::from_millis((TRICKLE_GAP_TIME + 100) as u64));

        let pool_1 = mempool_1.lock().unwrap();
        let pool_2 = mempool_2.lock().unwrap();
        let pool_3 = mempool_3.lock().unwrap();
        // after half time, only one of 2, 3 will receive the transaction

        assert_eq!(pool_1.size(), 1);
        assert_ne!(pool_2.size(), pool_3.size());
        assert_eq!(pool_2.size() + pool_3.size(), 1);
        drop(pool_1);
        drop(pool_2);
        drop(pool_3);

        // after one and a half time, both of 2, 3 will receive the transaction

        sleep(time::Duration::from_millis((TRICKLE_GAP_TIME * 2 + 100) as u64));

        let pool_1 = mempool_1.lock().unwrap();
        let pool_2 = mempool_2.lock().unwrap();
        let pool_3 = mempool_3.lock().unwrap();
        // after half time, only one of 2, 3 will receive the transaction

        assert_eq!(pool_1.size(), 1);
        assert_eq!(pool_1.size(), pool_2.size());
        assert_eq!(pool_2.size(), pool_3.size());
    }

    #[test]
    fn test_diffusion_transaction_relay() {
        let p2p_addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19031);
        let p2p_addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19032);
        let p2p_addr_3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19033);
        let p2p_addr_4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19034);
        let p2p_addr_5 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19035);

        let (server_1, _, mut generator_1, _, mempool_1, _, _) = new_server_env(p2p_addr_1, Spreader::Diffusion, false);
        let (server_2, _, generator_2, _, mempool_2, _, _) = new_server_env(p2p_addr_2, Spreader::Diffusion, false);
        let (server_3, _, generator_3, _, mempool_3, _, _) = new_server_env(p2p_addr_3, Spreader::Diffusion, false);
        let (server_4, _, _, _, mempool_4, _, _) = new_server_env(p2p_addr_4, Spreader::Diffusion, false);
        let (_, _, _, _, mempool_5, _, _) = new_server_env(p2p_addr_5, Spreader::Diffusion, false);

        // all other servers directly connect to server 1
        let peers_list = vec![p2p_addr_2, p2p_addr_3, p2p_addr_4, p2p_addr_5];
        connect_peers(&server_1, &peers_list);

        let mempool_list = vec![mempool_2.clone(), mempool_3.clone(),
                                mempool_4.clone(), mempool_5.clone()];

        generator_1.generating();
        let mut sleep_time = DIFFUSION_BASE_GAP_TIME as f64;
        for i in 1..5 {
            sleep_time *= DIFFUSION_RATE;
            sleep(time::Duration::from_millis(sleep_time as u64));
            check_mempools_total_size(&mempool_list, i);
        }
    }

    #[test]
    fn test_dandelion_reset_epoch() {
        let p2p_addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 18234);
        let p2p_addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 18335);
        let (_, _, _, _, mempool, _, _) = new_server_env(p2p_addr_1, Spreader::Diffusion, false);

        let stream = std::net::TcpStream::connect(p2p_addr_1).unwrap();
        let mio_stream = mio::net::TcpStream::from_stream(stream).unwrap();
        let mut peers = slab::Slab::<peer::Context>::new();
        let vacant = peers.vacant_entry();
        let key: usize = vacant.key();
        let mut peer_list = Vec::<usize>::new();
        let (peer_ctx, handle) = peer::new(mio_stream, peer::Direction::Outgoing, key).unwrap();
        vacant.insert(peer_ctx);
        peer_list.push(key);
        let trans = vec![helper::generate_random_signed_transaction()];
        let msg = Message::NewDandelionTransactions(trans);
        let server_handle = server::tests::fake_server_handle();
        let (mut dandelion_sreapder, ctx) = DandelionSpreader::new(mempool, server_handle);
        ctx.start();
        dandelion_sreapder.set_epoch_period(10);
        dandelion_sreapder.spread(&peers, &peer_list, msg.clone(), Some(key));
        assert_eq!(key, *dandelion_sreapder.target_index.lock().unwrap());
        thread::sleep(time::Duration::from_millis(15));
        assert_eq!(usize::max_value(), *dandelion_sreapder.target_index.lock().unwrap());
    }

    fn test_dandelion_transaction_relay() {
        let p2p_addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19041);
        let p2p_addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19042);
        let p2p_addr_3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19043);

        let known_peers_1 = vec![p2p_addr_2, p2p_addr_3];
        let known_peers_2 = vec![p2p_addr_1, p2p_addr_3];
        let known_peers_3 = vec![p2p_addr_1, p2p_addr_2];

        let (server_1, _miner_ctx_1, mut generator_1, _blockchain_1, mempool_1, _, _) = new_server_env(p2p_addr_1, Spreader::Dandelion, false);
        let (server_2, _miner_ctx_2, generator_2, _blockchain_2, mempool_2, _, _) = new_server_env(p2p_addr_2, Spreader::Dandelion, false);
        let (server_3, _miner_ctx_3, generator_3, _blockchain_3, mempool_3, _, _) = new_server_env(p2p_addr_3, Spreader::Dandelion, false);

        connect_peers(&server_1, &known_peers_1);
        connect_peers(&server_2, &known_peers_2);
        connect_peers(&server_3, &known_peers_3);

        generator_1.generating();
        sleep(time::Duration::from_millis(100));

        let pool_1 = mempool_1.lock().unwrap();
        let pool_2 = mempool_2.lock().unwrap();
        let pool_3 = mempool_3.lock().unwrap();

        //Short transmission time: assume haven't switch to diffusion yet
        assert_eq!(pool_1.size(), 1);
        assert!(pool_2.empty());
        assert!(pool_3.empty());
        drop(pool_1);
        drop(pool_2);
        drop(pool_3);

        sleep(time::Duration::from_secs(1));

        let pool_1 = mempool_1.lock().unwrap();
        let pool_2 = mempool_2.lock().unwrap();
        let pool_3 = mempool_3.lock().unwrap();
        //Long enough to check mempool
        assert_eq!(pool_1.size(), 1);
        assert_eq!(pool_1.size(), pool_2.size());
        assert_eq!(pool_2.size(), pool_3.size());
    }
}