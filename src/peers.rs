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
}

#[cfg(any(test, test_utilities))]
mod test {
    use super::*;
    use crate::helper::generate_random_h160;

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