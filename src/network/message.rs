use serde::{Serialize, Deserialize};

use crate::block::Block;
use crate::crypto::hash::{H256, H160};
use crate::transaction::SignedTransaction;

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
    NewAddresses(Vec<H160>),
    Introduce(H160),
}
