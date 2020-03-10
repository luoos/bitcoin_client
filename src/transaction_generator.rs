use std::sync::{Arc, Mutex};
use std::thread;
use std::time;
use log::info;

use crate::network::server::Handle as ServerHandle;
use crate::network::message::Message;
use crate::mempool::MemPool;
use crate::helper::generate_random_signed_transaction;
use crate::crypto::hash::Hashable;
use crate::config::TRANSACTION_GENERATE_INTERVAL;

#[derive(Clone)]
pub struct Context {
    server: ServerHandle,
    mempool: Arc<Mutex<MemPool>>,
}

pub fn new(
    server: &ServerHandle,
    mempool: &Arc<Mutex<MemPool>>,
) -> Context {
    Context {server: server.clone(), mempool: Arc::clone(mempool)}
}

impl Context {
    pub fn start(mut self) {
        thread::Builder::new()
            .name("transaction_generator".to_string())
            .spawn(move|| {
                self.transaction_generator_loop();
            })
            .unwrap();
        info!("Transaction generator Started");
    }

    pub fn transaction_generator_loop(&mut self) {
        loop {
            self.generating();

            let sleep_itv = time::Duration::from_millis(TRANSACTION_GENERATE_INTERVAL);
            thread::sleep(sleep_itv);
        }
    }

    //For now, just call generate_random_signed_transaction
    pub fn generating(&mut self) {
        let new_t = generate_random_signed_transaction();
        let mut mempool = self.mempool.lock().unwrap();
        if mempool.add_with_check(&new_t) {
            info!("Generate new transaction with {} input {} output! Now mempool has {} transaction",
                new_t.transaction.inputs.len(), new_t.transaction.outputs.len(), mempool.size());
            let vec = vec![new_t.hash().clone()];
            self.server.broadcast(Message::NewTransactionHashes(vec));
        }
        drop(mempool);
    }
}

#[cfg(any(test, test_utilities))]
mod tests {
    use crate::miner::tests::{new_server_env, connect_peers};
    use std::net::{SocketAddr, IpAddr, Ipv4Addr};
    use std::thread::sleep;
    use std::time;

    #[test]
    fn test_transaction_relay() {
        let p2p_addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17021);
        let p2p_addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17022);
        let p2p_addr_3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17023);

        let (_server_1, _miner_ctx_1, mut generator_1,  _blockchain_1, mempool_1) = new_server_env(p2p_addr_1);
        let (server_2, _miner_ctx_2, mut generator_2, _blockchain_2, mempool_2) = new_server_env(p2p_addr_2);
        let (server_3, _miner_ctx_3, mut generator_3, _blockchain_3, mempool_3) = new_server_env(p2p_addr_3);

        let peers_1 = vec![p2p_addr_1];
        connect_peers(&server_2, peers_1);
        let peers_2 = vec![p2p_addr_2];
        connect_peers(&server_3, peers_2);

        generator_1.generating();
        sleep(time::Duration::from_millis(100));

        let pool_1 = mempool_1.lock().unwrap();
        let pool_2 = mempool_2.lock().unwrap();
        let pool_3 = mempool_3.lock().unwrap();
        assert_eq!(pool_1.size(), 1);
        assert_eq!(pool_1.size(), pool_2.size());
        assert_eq!(pool_1.size(), pool_3.size());
        drop(pool_1);
        drop(pool_2);
        drop(pool_3);

        generator_2.generating();
        sleep(time::Duration::from_millis(100));

        let pool_1 = mempool_1.lock().unwrap();
        let pool_2 = mempool_2.lock().unwrap();
        let pool_3 = mempool_3.lock().unwrap();
        assert_eq!(pool_1.size(), 2);
        assert_eq!(pool_1.size(), pool_2.size());
        assert_eq!(pool_1.size(), pool_3.size());
        drop(pool_1);
        drop(pool_2);
        drop(pool_3);

        generator_3.generating();
        sleep(time::Duration::from_millis(100));

        let pool_1 = mempool_1.lock().unwrap();
        let pool_2 = mempool_2.lock().unwrap();
        let pool_3 = mempool_3.lock().unwrap();
        assert_eq!(pool_1.size(), 3);
        assert_eq!(pool_1.size(), pool_2.size());
        assert_eq!(pool_1.size(), pool_3.size());
        drop(pool_1);
        drop(pool_2);
        drop(pool_3);
    }
}