use std::collections::HashSet;

use crate::crypto::hash::H160;

pub struct Peers {
    pub addrs: HashSet<H160>,
}

impl Peers {
    pub fn new() -> Self {
        Self {addrs: HashSet::new()}
    }

    pub fn insert(&mut self, addr: &H160) {
        self.addrs.insert(addr.clone());
    }

    pub fn remove(&mut self, addr: &H160) {
        self.addrs.remove(addr);
    }

    pub fn contains(&self, addr: &H160) -> bool {
        self.addrs.contains(addr)
    }

    pub fn get_all_peers_addrs(&self) -> Vec<H160> {
        let addrs: Vec<H160> = self.addrs.iter()
            .map(|addr|addr.clone()).collect();
        addrs
    }

    pub fn size(&self) -> usize {
        self.addrs.len()
    }
}

#[cfg(any(test, test_utilities))]
mod test {
    use super::*;
    use crate::helper::*;
    use crate::network::message::Message;

    use std::net::{SocketAddr, IpAddr, Ipv4Addr};
    use std::time;
    use std::thread;

    #[test]
    fn test_peers_addr_relay() {
        let p2p_addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17061);
        let p2p_addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17062);
        let p2p_addr_3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17063);
        let p2p_addr_4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17064);

        let (server_1, _, _, _, _, peers_1, addr_1) = new_server_env(p2p_addr_1);
        let (server_2, _, _, _, _, peers_2, addr_2) = new_server_env(p2p_addr_2);
        let (server_3, _, _, _, _, peers_3, addr_3) = new_server_env(p2p_addr_3);
        let (server_4, _, _, _, _, peers_4, addr_4) = new_server_env(p2p_addr_4);

        // server_1 online but no connections
        server_1.broadcast(Message::Introduce(addr_1));
        thread::sleep(time::Duration::from_millis(100));

        let mut p_1 = peers_1.lock().unwrap();
        let mut p_2 = peers_2.lock().unwrap();
        let mut p_3 = peers_3.lock().unwrap();
        let mut p_4 = peers_4.lock().unwrap();
        assert_eq!(p_1.size(), 0);
        assert_eq!(p_2.size(), 0);
        drop(p_1);
        drop(p_2);
        drop(p_3);
        drop(p_4);

        // server_2 online & connect to server_1
        let server_peers_1 = vec![p2p_addr_1];
        connect_peers(&server_2, server_peers_1.clone());
        thread::sleep(time::Duration::from_millis(100));

        server_2.broadcast(Message::Introduce(addr_2));
        thread::sleep(time::Duration::from_millis(100));

        p_1 = peers_1.lock().unwrap();
        p_2 = peers_2.lock().unwrap();
        // Check bilateral broadcast
        assert_eq!(p_1.get_all_peers_addrs(), vec![addr_2]);
        assert_eq!(p_2.get_all_peers_addrs(), vec![addr_1]);
        drop(p_1);
        drop(p_2);

        // server_3 online & connect to server_2
        let server_peers_2 = vec![p2p_addr_2];
        connect_peers(&server_3, server_peers_2.clone());
        thread::sleep(time::Duration::from_millis(100));

        server_3.broadcast(Message::Introduce(addr_3));
        thread::sleep(time::Duration::from_millis(100));

        p_1 = peers_1.lock().unwrap();
        p_2 = peers_2.lock().unwrap();
        p_3 = peers_3.lock().unwrap();
        assert!(p_1.contains(&addr_2) && p_1.contains(&addr_3));
        assert!(p_2.contains(&addr_1) && p_2.contains(&addr_3));
        assert!(p_3.contains(&addr_1) && p_3.contains(&addr_2));
        drop(p_1);
        drop(p_2);
        drop(p_3);

        // server_4 online & connect to server_1,2
        let server_peers_12 = vec![p2p_addr_1, p2p_addr_2];
        connect_peers(&server_4, server_peers_12.clone());
        thread::sleep(time::Duration::from_millis(100));

        server_4.broadcast(Message::Introduce(addr_4));
        thread::sleep(time::Duration::from_millis(100));

        p_1 = peers_1.lock().unwrap();
        p_2 = peers_2.lock().unwrap();
        p_3 = peers_3.lock().unwrap();
        p_4 = peers_4.lock().unwrap();
        assert!(p_1.size() == 3 && !p_1.contains(&addr_1));
        assert!(p_2.size() == 3 && !p_2.contains(&addr_2));
        assert!(p_3.size() == 3 && !p_3.contains(&addr_3));
        assert!(p_4.size() == 3 && !p_4.contains(&addr_4));
    }

    #[test]
    fn test_peers() {
        let addr = generate_random_h160();
        let addr2 = generate_random_h160();
        let mut peers = Peers::new();
        assert!(!peers.contains(&addr));
        peers.insert(&addr);
        assert!(peers.contains(&addr));
        peers.insert(&addr2);
        assert!(peers.contains(&addr2));
        peers.remove(&addr);
        assert!(!peers.contains(&addr));
        assert!(peers.contains(&addr2));
        peers.remove(&addr2);
        assert!(!peers.contains(&addr2));
    }
}