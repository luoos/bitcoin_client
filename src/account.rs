use ring::signature::{KeyPair, Ed25519KeyPair, ED25519_PUBLIC_KEY_LEN};
use ring;

use super::crypto::hash::H160;
use std::sync::Arc;

pub struct Account {
    pub key_pair: Arc<Ed25519KeyPair>,
    pub addr: H160,
    pub pub_key: [u8; ED25519_PUBLIC_KEY_LEN],
}

impl Account {
    pub fn new(key_pair: Arc<Ed25519KeyPair>) -> Self {
        let mut pub_key: [u8; ED25519_PUBLIC_KEY_LEN] = [0; ED25519_PUBLIC_KEY_LEN];
        pub_key[..].copy_from_slice(&key_pair.public_key().as_ref()[..]);
        let addr: H160 = ring::digest::digest(&ring::digest::SHA256, &pub_key).into();
        Self {key_pair: key_pair, addr: addr, pub_key: pub_key}
    }
}

#[cfg(any(test, test_utilities))]
mod test {
    use ring;
    use super::*;
    use crate::crypto::key_pair;
    use crate::crypto::hash::H256;

    #[test]
    fn test_account() {
        let key = Arc::new(key_pair::random());
        let pub_key = key.public_key().clone();
        let account = Account::new(key);
        let pub_key_hash: H256 = ring::digest::digest(&ring::digest::SHA256, pub_key.as_ref()).into();
        let addr: H160 = pub_key_hash.into();
        assert_eq!(addr, account.addr);
    }
}