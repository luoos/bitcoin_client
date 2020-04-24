use std::collections::{HashSet, HashMap};

use crate::crypto::hash::H160;

use ring::signature::ED25519_PUBLIC_KEY_LEN;

pub struct Peers {
    pub addrs: HashSet<H160>,
    pub info_map: HashMap<H160, (Box<[u8; ED25519_PUBLIC_KEY_LEN]>, u16)>
}

impl Peers {
    pub fn new() -> Self {
        Self {addrs: HashSet::new(), info_map: HashMap::new()}
    }

    pub fn insert(&mut self, addr: &H160, pub_key : Box<[u8; ED25519_PUBLIC_KEY_LEN]>, port: u16) {
        self.addrs.insert(addr.clone());
        self.info_map.insert(addr.clone(), (pub_key, port));
    }

    pub fn remove(&mut self, addr: &H160) {
        self.addrs.remove(addr);
        self.info_map.remove(addr);
    }

    pub fn contains(&self, addr: &H160) -> bool {
        self.addrs.contains(addr)
    }

    pub fn get_all_peers_info(&self) -> Vec<(H160, Box<[u8; ED25519_PUBLIC_KEY_LEN]>, u16)> {
        let info: Vec<(H160, Box<[u8; ED25519_PUBLIC_KEY_LEN]>, u16)> = self.addrs.iter()
            .map(|addr|(addr.clone(),
                        self.info_map.get(addr).unwrap().clone().0, // public key
                        self.info_map.get(addr).unwrap().clone().1)).collect(); // port number
        info
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
    use crate::spread::Spreader;
    use crate::crypto::key_pair;
    use ring::signature::KeyPair;

    use std::net::{SocketAddr, IpAddr, Ipv4Addr};
    use std::time;
    use std::thread;

    #[test]
    fn test_peers_addr_relay() {
        let p2p_addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17061);
        let p2p_addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17062);
        let p2p_addr_3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17063);
        let p2p_addr_4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17064);

        let (server_1, _, _, _, _, peers_1, account_1) = new_server_env(p2p_addr_1, Spreader::Default, false);
        let (server_2, _, _, _, _, peers_2, account_2) = new_server_env(p2p_addr_2, Spreader::Default, false);
        let (server_3, _, _, _, _, peers_3, account_3) = new_server_env(p2p_addr_3, Spreader::Default, false);
        let (server_4, _, _, _, _, peers_4, account_4) = new_server_env(p2p_addr_4, Spreader::Default, false);

        let addr_1 = account_1.addr;
        let addr_2 = account_2.addr;
        let addr_3 = account_3.addr;
        let addr_4 = account_4.addr;

        let pub_key_1 = account_1.get_pub_key();
        let pub_key_2 = account_2.get_pub_key();
        let pub_key_3 = account_3.get_pub_key();
        let pub_key_4 = account_4.get_pub_key();

        let port_1 = account_1.port;
        let port_2 = account_2.port;
        let port_3 = account_3.port;
        let port_4 = account_4.port;


        // server_1 online but no connections
        server_1.broadcast(Message::Introduce((addr_1, pub_key_1.clone(), port_1)));
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
        connect_peers(&server_2, &server_peers_1);
        thread::sleep(time::Duration::from_millis(100));

        server_2.broadcast(Message::Introduce((addr_2, pub_key_2.clone(), port_2)));
        thread::sleep(time::Duration::from_millis(100));

        p_1 = peers_1.lock().unwrap();
        p_2 = peers_2.lock().unwrap();
        // Check bilateral broadcast
        assert_eq!(p_1.get_all_peers_info(), vec![(addr_2, pub_key_2, port_2)]);
        assert_eq!(p_2.get_all_peers_info(), vec![(addr_1, pub_key_1, port_1)]);
        drop(p_1);
        drop(p_2);

        // server_3 online & connect to server_2
        let server_peers_2 = vec![p2p_addr_2];
        connect_peers(&server_3, &server_peers_2);
        thread::sleep(time::Duration::from_millis(100));

        server_3.broadcast(Message::Introduce((addr_3, pub_key_3, port_3)));
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
        connect_peers(&server_4, &server_peers_12);
        thread::sleep(time::Duration::from_millis(100));

        server_4.broadcast(Message::Introduce((addr_4, pub_key_4, port_4)));
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

        let peer_key_pair1 = key_pair::random();
        let peer_key_pair2 = key_pair::random();

        let mut bytes_pub_key1: [u8; ED25519_PUBLIC_KEY_LEN] = [0; ED25519_PUBLIC_KEY_LEN];
        bytes_pub_key1[..].copy_from_slice(&peer_key_pair1.public_key().as_ref()[..]);
        let mut bytes_pub_key2: [u8; ED25519_PUBLIC_KEY_LEN] = [0; ED25519_PUBLIC_KEY_LEN];
        bytes_pub_key2[..].copy_from_slice(&peer_key_pair2.public_key().as_ref()[..]);

        let port1 = 1111u16;
        let port2 = 2222u16;

        let mut peers = Peers::new();
        assert!(!peers.contains(&addr));
        peers.insert(&addr, Box::new(bytes_pub_key1), port1);
        assert!(peers.contains(&addr));
        peers.insert(&addr2, Box::new(bytes_pub_key2), port2);
        assert!(peers.contains(&addr2));
        peers.remove(&addr);
        assert!(!peers.contains(&addr));
        assert!(peers.contains(&addr2));
        peers.remove(&addr2);
        assert!(!peers.contains(&addr2));
    }
}