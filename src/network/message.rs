use serde::{Serialize, Deserialize};

use crate::block::Block;
use crate::crypto::hash::{H256, H160};
use crate::transaction::SignedTransaction;
use ring::signature::ED25519_PUBLIC_KEY_LEN;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Message {
    Ping(String),
    Pong(String),
    NewBlockHashes(Vec<H256>),
    GetBlocks(Vec<H256>),
    Blocks(Vec<Block>),
    NewTransactionHashes(Vec<H256>),
    GetTransactions(Vec<H256>),
    Transactions(Vec<SignedTransaction>),
    NewPeers(Vec<(H160, Box<[u8; ED25519_PUBLIC_KEY_LEN]>, u16)>),
    Introduce((H160, Box<[u8; ED25519_PUBLIC_KEY_LEN]>, u16)),
}
