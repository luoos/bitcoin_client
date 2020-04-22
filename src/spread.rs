use crate::network::{peer, message};
use crate::network::peer::Handle;
use crate::helper;

use std::thread;
use std::sync::{Mutex, Arc};
use std::sync::mpsc::{channel, Receiver};

extern crate chrono;

use timer::{MessageTimer, Guard};
use std::collections::HashMap;

extern crate timer;

pub trait Spreading {
    fn spread(&self, peers: &slab::Slab<peer::Context>, peer_index: &Vec<usize>, msg: message::Message);
}

#[derive(Copy, Clone)]
pub enum Spreader {
    Default,
    Trickle,
    Diffusion,
    Dandelion,
    DandelionPlus,
}

struct DefaultSpreader {
    pub timer: MessageTimer<(i64, Handle, message::Message)>,
    guard_map: Arc<Mutex<HashMap<i64, Guard>>>,
}

fn new_base() -> (MessageTimer<(i64, Handle, message::Message)>, Arc<Mutex<HashMap<i64, Guard>>>, Context) {
    let (sender, receiver) = channel();
    let timer = MessageTimer::new(sender);
    let guard_map = Arc::new(Mutex::new(HashMap::new()));
    let context = Context { receiver, guard_map: guard_map.clone() };

    return (timer, guard_map, context);
}

impl Spreading for DefaultSpreader {
    fn spread(&self, peers: &slab::Slab<peer::Context>, peer_list: &Vec<usize>, msg: message::Message) {
        let mut map = self.guard_map.lock().unwrap();
        for peer_id in peer_list {
            let now_nano = helper::get_current_time_in_nano();
            let guard = self.timer.schedule_with_delay(chrono::Duration::milliseconds(0),
                                                       (now_nano, peers[*peer_id].handle.clone(), msg.clone()));
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

pub struct Context {
    pub receiver: Receiver<(i64, Handle, message::Message)>,
    guard_map: Arc<Mutex<HashMap<i64, Guard>>>,
}

impl Context {
    pub fn message_loop(&mut self) {
        loop {
            match self.receiver.recv() {
                Ok(content) => {
                    // TODO may need to check the concerning handle peer exist
                    let handle = content.1;
                    let msg = content.2;
                    handle.write(msg);
                    self.guard_map.lock().unwrap().remove(&content.0);
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

const TRICKLE_GAP_TIME: i64 = 200;

struct TrickleSpreader {
    pub timer: MessageTimer<(i64, Handle, message::Message)>,
    guard_map: Arc<Mutex<HashMap<i64, Guard>>>,
}

impl TrickleSpreader {
    pub fn new() -> (Self, Context) {
        let (timer, guard_map, context) = new_base();
        (TrickleSpreader { timer, guard_map }, context)
    }
}

impl Spreading for TrickleSpreader {
    fn spread(&self, peers: &slab::Slab<peer::Context>, peer_list: &Vec<usize>, msg: message::Message) {
        let shuffled_peers_list = helper::gen_shuffled_peer_list(peer_list);
        let mut map = self.guard_map.lock().unwrap();
        for (i, peer_id) in shuffled_peers_list.iter().enumerate() {
            let now_nano = helper::get_current_time_in_nano();
            let guard = self.timer.schedule_with_delay(chrono::Duration::milliseconds(TRICKLE_GAP_TIME * (i + 1) as i64),
                                                       (now_nano, peers[*peer_id].handle.clone(), msg.clone()));
            map.insert(now_nano, guard);
        }
    }
}

const DIFFUSION_BASE_GAP_TIME: i64 = 100;
const DIFFUSION_RATE: f64 = 1.5;

struct DiffusionSpreader {
    timer: MessageTimer<(i64, Handle, message::Message)>,
    guard_map: Arc<Mutex<HashMap<i64, Guard>>>,
}

impl DiffusionSpreader {
    pub fn new() -> (Self, Context) {
        let (timer, guard_map, context) = new_base();
        (DiffusionSpreader { timer, guard_map }, context)
    }
}

impl Spreading for DiffusionSpreader {
    fn spread(&self, peers: &slab::Slab<peer::Context>, peer_list: &Vec<usize>, msg: message::Message) {
        let mut gap_time = DIFFUSION_BASE_GAP_TIME;
        let shuffled_peers_list = helper::gen_shuffled_peer_list(peer_list);
        let mut map = self.guard_map.lock().unwrap();
        for peer_id in shuffled_peers_list.iter() {
            let now_nano = helper::get_current_time_in_nano();
            let guard = self.timer.schedule_with_delay(chrono::Duration::milliseconds(gap_time),
                                                       (now_nano, peers[*peer_id].handle.clone(), msg.clone()));
            gap_time = (gap_time as f64 * DIFFUSION_RATE) as i64;
            map.insert(now_nano, guard);
        }
    }
}

struct DandelionSpreader {
    timer: MessageTimer<(i64, Handle, message::Message)>,
    guard_map: Arc<Mutex<HashMap<i64, Guard>>>,
}

impl DandelionSpreader {
    pub fn new() -> (Self, Context) {
        let (timer, guard_map, context) = new_base();
        (DandelionSpreader { timer, guard_map }, context)
    }
}

impl Spreading for DandelionSpreader {
    fn spread(&self, peers: &slab::Slab<peer::Context>, peer_list: &Vec<usize>, msg: message::Message) {
        // TODO
    }
}

struct DandelionPlusSpreader {
    timer: MessageTimer<(i64, Handle, message::Message)>,
    guard_map: Arc<Mutex<HashMap<i64, Guard>>>,
}

impl DandelionPlusSpreader {
    pub fn new() -> (Self, Context) {
        let (timer, guard_map, context) = new_base();
        (DandelionPlusSpreader { timer, guard_map }, context)
    }
}

impl Spreading for DandelionPlusSpreader {
    fn spread(&self, peers: &slab::Slab<peer::Context>, peer_list: &Vec<usize>, msg: message::Message) {
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

    use crate::helper::*;
    use super::*;


    #[test]
    fn test_trickle_transaction_relay() {
        let p2p_addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 18031);
        let p2p_addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 18032);
        let p2p_addr_3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 18033);

        let (_server_1, _miner_ctx_1, mut generator_1, _blockchain_1, mempool_1, _, _) = new_server_env(p2p_addr_1, Spreader::Trickle);
        let (server_2, _miner_ctx_2, generator_2, _blockchain_2, mempool_2, _, _) = new_server_env(p2p_addr_2, Spreader::Trickle);
        let (server_3, _miner_ctx_3, generator_3, _blockchain_3, mempool_3, _, _) = new_server_env(p2p_addr_3, Spreader::Trickle);

        let peers_1 = vec![p2p_addr_1];
        connect_peers(&server_2, peers_1);
        let peers_2 = vec![p2p_addr_2];
        connect_peers(&server_3, peers_2);

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

        let (_server_1, _miner_ctx_1, mut generator_1, _blockchain_1, mempool_1, _, _) = new_server_env(p2p_addr_1, Spreader::Diffusion);
        let (server_2, _miner_ctx_2, generator_2, _blockchain_2, mempool_2, _, _) = new_server_env(p2p_addr_2, Spreader::Diffusion);
        let (server_3, _miner_ctx_3, generator_3, _blockchain_3, mempool_3, _, _) = new_server_env(p2p_addr_3, Spreader::Diffusion);

        let peers_1 = vec![p2p_addr_1];
        connect_peers(&server_2, peers_1);
        let peers_2 = vec![p2p_addr_2];
        connect_peers(&server_3, peers_2);

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
}