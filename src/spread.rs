use crate::network::peer;
use crate::network::message::Message;
use crate::network::peer::Handle;
use crate::helper;
use crate::config::EPOCH_MS;

use std::thread;
use std::sync::{Mutex, Arc};
use std::sync::mpsc::{channel, Receiver};

extern crate chrono;

use timer::{MessageTimer, Guard};
use std::collections::HashMap;

extern crate timer;

pub trait Spreading {
    fn spread(&mut self, peers: &slab::Slab<peer::Context>, peer_index: &Vec<usize>, msg: Message);
}

#[derive(Copy, Clone)]
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
    ResetEpoch(i64, Arc<Mutex<usize>>),
}

pub struct Context {
    pub receiver: Receiver<TimerTask>,
    guard_map: Arc<Mutex<HashMap<i64, Guard>>>,
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
                        TimerTask::ResetEpoch(nano, target_index) => {
                            *target_index.lock().unwrap() = usize::max_value();
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

fn new_base() -> (MessageTimer<TimerTask>, Arc<Mutex<HashMap<i64, Guard>>>, Context) {
    let (sender, receiver) = channel();
    let timer = MessageTimer::new(sender);
    let guard_map = Arc::new(Mutex::new(HashMap::new()));
    let context = Context { receiver, guard_map: guard_map.clone() };

    return (timer, guard_map, context);
}

impl Spreading for DefaultSpreader {
    fn spread(&mut self, peers: &slab::Slab<peer::Context>, peer_list: &Vec<usize>, msg: Message) {
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
    pub fn new() -> (Self, Context) {
        let (timer, guard_map, context) = new_base();
        (DefaultSpreader { timer, guard_map }, context)
    }
}

const TRICKLE_GAP_TIME: i64 = 200;

struct TrickleSpreader {
    pub timer: MessageTimer<TimerTask>,
    guard_map: Arc<Mutex<HashMap<i64, Guard>>>,
}

impl TrickleSpreader {
    pub fn new() -> (Self, Context) {
        let (timer, guard_map, context) = new_base();
        (TrickleSpreader { timer, guard_map }, context)
    }
}

impl Spreading for TrickleSpreader {
    fn spread(&mut self, peers: &slab::Slab<peer::Context>, peer_list: &Vec<usize>, msg: Message) {
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

const DIFFUSION_BASE_GAP_TIME: i64 = 100;
const DIFFUSION_RATE: f64 = 1.5;

struct DiffusionSpreader {
    timer: MessageTimer<TimerTask>,
    guard_map: Arc<Mutex<HashMap<i64, Guard>>>,
}

impl DiffusionSpreader {
    pub fn new() -> (Self, Context) {
        let (timer, guard_map, context) = new_base();
        (DiffusionSpreader { timer, guard_map }, context)
    }
}

impl Spreading for DiffusionSpreader {
    fn spread(&mut self, peers: &slab::Slab<peer::Context>, peer_list: &Vec<usize>, msg: Message) {
        let mut gap_time = DIFFUSION_BASE_GAP_TIME;
        let shuffled_peers_list = helper::gen_shuffled_peer_list(peer_list);
        let mut map = self.guard_map.lock().unwrap();
        for peer_id in shuffled_peers_list.iter() {
            let now_nano = helper::get_current_time_in_nano();
            let guard = self.timer.schedule_with_delay(chrono::Duration::milliseconds(gap_time),
                                                       TimerTask::PeerWrite(now_nano, peers[*peer_id].handle.clone(), msg.clone()));
            gap_time = (gap_time as f64 * DIFFUSION_RATE) as i64;
            map.insert(now_nano, guard);
        }
    }
}

struct DandelionSpreader {
    timer: MessageTimer<TimerTask>,
    guard_map: Arc<Mutex<HashMap<i64, Guard>>>,
    target_index: Arc<Mutex<usize>>,
    epoch_period_ms: i64,
}

impl DandelionSpreader {
    pub fn new() -> (Self, Context) {
        let (timer, guard_map, context) = new_base();
        (DandelionSpreader {
            timer, guard_map,
            target_index: Arc::new(Mutex::new(usize::max_value())),
            epoch_period_ms: EPOCH_MS },
        context)
    }

    #[cfg(any(test))]
    fn set_epoch_period(&mut self, period: i64) {
        self.epoch_period_ms = period;
    }
}

impl Spreading for DandelionSpreader {
    fn spread(&mut self, peers: &slab::Slab<peer::Context>, peer_list: &Vec<usize>, msg: Message) {
        // check phase 1 or 2

        // run phase 2

        // phase 1
        let target_index: usize = *self.target_index.lock().unwrap();
        if let Some(peer) = peers.get(target_index) {
            peer.handle.write(msg);
        } else if peer_list.len() > 0 {
            let random_i = helper::gen_random_num(0, peer_list.len() as u64 - 1) as usize;
            // Arc::get_mut(&mut self.target_index).unwrap() = peer_list[random_i as usize];
            let peer_list_index = peer_list[random_i];
            *self.target_index.lock().unwrap() = peer_list_index;
            peers[peer_list_index].handle.write(msg);
            let now_nano = helper::get_current_time_in_nano();
            let guard = self.timer.schedule_with_delay(chrono::Duration::microseconds(self.epoch_period_ms),
                TimerTask::ResetEpoch(now_nano, self.target_index.clone()));
            self.guard_map.lock().unwrap().insert(now_nano, guard);
        }
    }
}

struct DandelionPlusSpreader {
    timer: MessageTimer<TimerTask>,
    guard_map: Arc<Mutex<HashMap<i64, Guard>>>,
}

impl DandelionPlusSpreader {
    pub fn new() -> (Self, Context) {
        let (timer, guard_map, context) = new_base();
        (DandelionPlusSpreader { timer, guard_map }, context)
    }
}

impl Spreading for DandelionPlusSpreader {
    fn spread(&mut self, peers: &slab::Slab<peer::Context>, peer_list: &Vec<usize>, msg: Message) {
        // TODO
    }
}

pub fn get_spreader(key: Spreader) -> (Box<dyn Spreading + Send>, Context) {
    match key {
        Spreader::Default => {
            let (spreader, ctx) = DefaultSpreader::new();
            (Box::new(spreader), ctx)
        }
        Spreader::Trickle => {
            let (spreader, ctx) = TrickleSpreader::new();
            (Box::new(spreader), ctx)
        }
        Spreader::Diffusion => {
            let (spreader, ctx) = DiffusionSpreader::new();
            (Box::new(spreader), ctx)
        }
        Spreader::Dandelion => {
            let (spreader, ctx) = DandelionSpreader::new();
            (Box::new(spreader), ctx)
        }
        Spreader::DandelionPlus => {
            let (spreader, ctx) = DandelionPlusSpreader::new();
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

        let (_server_1, _miner_ctx_1, mut generator_1, _blockchain_1, mempool_1, _, _) = new_server_env(p2p_addr_1, Spreader::Diffusion, false);
        let (server_2, _miner_ctx_2, generator_2, _blockchain_2, mempool_2, _, _) = new_server_env(p2p_addr_2, Spreader::Diffusion, false);
        let (server_3, _miner_ctx_3, generator_3, _blockchain_3, mempool_3, _, _) = new_server_env(p2p_addr_3, Spreader::Diffusion, false);

        let peers_1 = vec![p2p_addr_1];
        connect_peers(&server_2, &peers_1);
        let peers_2 = vec![p2p_addr_2];
        connect_peers(&server_3, &peers_2);

        generator_1.generating();
        sleep(time::Duration::from_millis((DIFFUSION_BASE_GAP_TIME) as u64 + 50u64));

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

        sleep(time::Duration::from_millis((DIFFUSION_BASE_GAP_TIME as f64 * DIFFUSION_RATE) as u64 + 50u64));

        let pool_1 = mempool_1.lock().unwrap();
        let pool_2 = mempool_2.lock().unwrap();
        let pool_3 = mempool_3.lock().unwrap();
        // after half time, only one of 2, 3 will receive the transaction

        assert_eq!(pool_1.size(), 1);
        assert_eq!(pool_1.size(), pool_2.size());
        assert_eq!(pool_2.size(), pool_3.size());
    }

    #[test]
    fn test_dandelion_reset_epoch() {
        let p2p_addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 18234);
        let p2p_addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 18335);
        let (_server_1, _miner_ctx_1, _, _blockchain_1, _, _, _) = new_server_env(p2p_addr_1, Spreader::Diffusion, false);

        let stream = std::net::TcpStream::connect(p2p_addr_1).unwrap();
        let mio_stream = mio::net::TcpStream::from_stream(stream).unwrap();
        let (peer_ctx, handle) = peer::new(mio_stream, peer::Direction::Outgoing).unwrap();
        let mut peers = slab::Slab::<peer::Context>::new();
        let vacant = peers.vacant_entry();
        let key: usize = vacant.key();
        let mut peer_list = Vec::<usize>::new();
        vacant.insert(peer_ctx);
        peer_list.push(key);
        let msg = Message::Ping("He".to_string());
        let (mut dandelion_sreapder, ctx) = DandelionSpreader::new();
        ctx.start();
        dandelion_sreapder.set_epoch_period(10);
        dandelion_sreapder.spread(&peers, &peer_list, msg.clone());
        assert_eq!(key, *dandelion_sreapder.target_index.lock().unwrap());
        thread::sleep(time::Duration::from_millis(15));
        assert_eq!(usize::max_value(), *dandelion_sreapder.target_index.lock().unwrap());
    }
}