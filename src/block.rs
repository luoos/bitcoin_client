use hex;
use ring::digest;
use serde::{Serialize, Deserialize};
use chrono::prelude::DateTime;
use chrono::Utc;
use std::time::{UNIX_EPOCH, Duration};
use std::collections::HashMap;
use crate::crypto::hash::{H256, H160, Hashable};
use crate::transaction::{SignedTransaction, PrintableTransaction};
use crate::crypto::merkle::MerkleTree;
use crate::config::DIFFICULTY;
use crate::helper::gen_difficulty_array;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub hash: H256,         // the hash of the header in this block
    pub index: usize,       // the distance from the genesis block
    pub header: Header,
    pub content: Content,   // transaction in this block
}

#[derive(Serialize, Deserialize)]
pub struct PrintableBlock {
    pub hash: String,
    pub parent_hash: String,
    pub index: usize,
    pub nonce: u32,
    pub difficulty: String,
    pub timestamp: String,
    pub merkle_root: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Header {
    pub parent: H256,
    pub nonce: u32,
    pub difficulty: H256,
    pub timestamp: u64,
    merkle_root: H256,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Content {
    pub trans: Vec<SignedTransaction>
}

#[derive(Serialize, Deserialize)]
pub struct PrintableContent {
    pub trans: Vec<PrintableTransaction>
}

#[derive(Clone)]
pub struct State (HashMap<(H256, u32), (u64, H160)>);

impl State {
    pub fn new() -> Self {
        let map: HashMap<(H256, u32), (u64, H160)> = HashMap::new();
        Self(map)
    }

    pub fn insert(&mut self, key: (H256, u32), val: (u64, H160)) {
        self.0.insert(key, val);
    }

    pub fn remove(&mut self, key: &(H256, u32)) -> Option<(u64, H160)> {
        return self.0.remove(key);
    }

    pub fn contains_key(&self, key: &(H256, u32)) -> bool {
        return self.0.contains_key(key);
    }

    pub fn get(&self, key: &(H256, u32)) -> Option<&(u64, H160)> {
        return self.0.get(key);
    }
}

impl Hashable for Block {
    fn hash(&self) -> H256 {
        self.hash.clone()
    }
}

impl PartialEq<Block> for Block {
    fn eq(&self, other: &Block) -> bool {
        let self_serialized_array = bincode::serialize(&self).unwrap();
        let other_serialized_array = bincode::serialize(other).unwrap();
        self_serialized_array == other_serialized_array
    }
}

impl Block {
    pub fn genesis() -> Self {
        let h: [u8; 32] = [0; 32];
        let difficulty: H256 = gen_difficulty_array(DIFFICULTY).into();

        let header = Header {
            parent: h.into(),
            nonce: 0,
            difficulty: difficulty,
            timestamp: 0,
            merkle_root: h.into(),
        };

        let content = Content {
            trans: Vec::<SignedTransaction>::new(),
        };

        Block {
            hash: h.into(),
            index: 0,
            header: header,
            content: content,
        }
    }

    pub fn new(header: Header, content: Content) -> Self {
        Self {
            hash: header.hash(),
            index: 0,
            header: header,
            content: content,
        }
    }

    pub fn get_hash(&self) -> H256 {
        self.hash.clone()
    }

    // Check transaction signature in content; if anyone fails, the whole block fails
    pub fn validate_signature(&self) -> bool {
        let trans = &self.content.trans;
        for t in trans.iter() {
            if !t.sign_check() {
                return false;
            }
        }
        true
    }

    // Try to generate a new state based on the parent_state
    // Validate all transactions, such as coinbase transaction and double-spend issue
    // return None if any check fails
    pub fn try_generate_state(&self, parent_state: &State) -> Option<State> {
        let mut state = parent_state.clone();
        let mut trans_iter = self.content.trans.iter();

        // check coinbase transaction
        if let Some(coinbase_tran) = trans_iter.next() {
            if !coinbase_tran.is_coinbase_tran() {
                return None;
            }
            let output = coinbase_tran.transaction.outputs[0].clone();
            state.insert((coinbase_tran.hash.clone(), 0),
                (output.val, output.rec_address));
        } else {
            return None;
        }

        // check non-coinbase transactions
        while let Some(tran) = trans_iter.next() {
            let mut balance = 0i64;
            let sender_addr: H160 = tran.sender_addr();

            // remove inputs from state
            for input in tran.transaction.inputs.iter() {
                match state.remove(&(input.pre_hash, input.index)) {
                    Some((val, owner_addr)) => {
                        if owner_addr != sender_addr {
                            return None;
                        }
                        balance += val as i64;
                    }
                    None => return None
                }
            }

            // add output to state
            for (index, output) in tran.transaction.outputs.iter().enumerate() {
                state.insert((tran.hash.clone(), index as u32),
                             (output.val, output.rec_address));
                balance -= output.val as i64;
            }

            // check balance
            if balance < 0 {
                return None;
            }
        }
        return Some(state);
    }

    #[cfg(any(test, test_utilities))]
    pub fn change_hash(&mut self, hash: &H256) {
        self.hash = hash.clone();
    }
}

impl PrintableBlock {
    pub fn from_block_vec(blocks: &Vec<Block>) -> Vec<PrintableBlock> {
        let mut pblocks = Vec::<PrintableBlock>::new();
        for b in blocks {
            let t = UNIX_EPOCH + Duration::from_millis(b.header.timestamp);
            let datetime = DateTime::<Utc>::from(t);
            let ts_str = datetime.format("%Y-%m-%d %H:%M:%S%.3f").to_string();
            let p = PrintableBlock {
                hash: hex::encode(&b.hash),
                parent_hash: hex::encode(&b.header.parent),
                index: b.index,
                nonce: b.header.nonce,
                difficulty: hex::encode(&b.header.difficulty),
                timestamp: ts_str,
                merkle_root: hex::encode(&b.header.merkle_root),
            };
            pblocks.push(p);
        }
        pblocks
    }
}

impl Header {
    pub fn new( parent: &H256, nonce: u32, timestamp: u128,
                difficulty: &H256, merkle_root: &H256) -> Self {
        Self {
            parent: parent.clone(),
            nonce: nonce,
            difficulty: difficulty.clone(),
            timestamp: timestamp as u64,
            merkle_root: merkle_root.clone(),
        }
    }

    pub fn hash(&self) -> H256 {
        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(self.parent.as_ref());
        ctx.update(&self.nonce.to_be_bytes());
        ctx.update(self.difficulty.as_ref());
        ctx.update(&self.timestamp.to_be_bytes());
        ctx.update(self.merkle_root.as_ref());
        ctx.finish().into()
    }

    pub fn change_nonce(&mut self) {
        self.nonce = self.nonce.overflowing_add(1).0;
    }
}

impl Content {
    pub fn new() -> Self {
        Self {
            trans: Vec::<SignedTransaction>::new(),
        }
    }

    pub fn new_with_trans(trans: &Vec<SignedTransaction>) -> Self {
        Self {
            trans: trans.clone(),
        }
    }

    pub fn add_tran(&mut self, tran: SignedTransaction) {
        self.trans.push(tran);
    }

    pub fn merkle_root(&self) -> H256 {
        let tree = MerkleTree::new(&self.trans);
        tree.root()
    }

    // Return a vector of hash for all transactions inside
    pub fn get_trans_hashes(&self) -> Vec<H256> {
        let hashes: Vec<H256> = self.trans.iter()
            .map(|t|t.hash).collect();
        hashes
    }
}

impl PrintableContent {
    pub fn from_content_vec(contents: &Vec<Content>) -> Vec<Self> {
        let mut pcontents = Vec::<Self>::new();
        for c in contents {
            let pts = PrintableTransaction::from_signedtx_vec(&c.trans);
            let pc = Self { trans: pts };
            pcontents.push(pc);
        }
        pcontents
    }
}

#[cfg(any(test, test_utilities))]
pub mod test {
    use ring::signature::KeyPair;
    use super::*;
    use crate::crypto::hash::H256;
    use crate::helper::*;
    use crate::crypto::key_pair;
    use crate::config::COINBASE_REWARD;
    use crate::transaction::{TxInput, TxOutput};

    #[test]
    fn test_genesis() {
        let g = Block::genesis();
        assert_eq!(0, g.index);
        assert_eq!(g.hash, H256::from([0u8; 32]));
        // let array: [u8; 32] = g.header.difficulty.into();
        assert!(DIFFICULTY > 0);
        assert!(DIFFICULTY < 256);
    }

    #[test]
    fn test_content_new_with_trans() {
        let mut trans = Vec::<SignedTransaction>::new();
        for _ in 0..3 {
            trans.push(generate_random_signed_transaction());
        }
        let _content = Content::new_with_trans(&trans);
    }

    #[test]
    fn test_difficulty() {
        let test_array1 = gen_difficulty_array(8);
        assert_eq!(0, test_array1[0]);
        assert_eq!(255, test_array1[1]);
        assert_eq!(255, test_array1[31]);

        let test_array1 = gen_difficulty_array(9);
        assert_eq!(0, test_array1[0]);
        assert_eq!(0x7f, test_array1[1]);
        assert_eq!(255, test_array1[31]);

        let test_array2 = gen_difficulty_array(10);
        assert_eq!(0, test_array2[0]);
        assert_eq!(63, test_array2[1]);
        assert_eq!(255, test_array2[2]);

        let test_array3 = gen_difficulty_array(15);
        assert_eq!(0, test_array3[0]);
        assert_eq!(1, test_array3[1]);
        assert_eq!(0, test_array3[0]);
        assert_eq!(255, test_array1[31]);

        let test_array4 = gen_difficulty_array(21);
        assert_eq!(0, test_array4[0]);
        assert_eq!(0, test_array4[1]);
        assert_eq!(7, test_array4[2]);
    }

    #[test]
    fn test_block_equality() {
        let rand_1: [u8; 32] = [0; 32];
        let rand_2: [u8; 32] = [1; 32];

        let content_1 = generate_random_content();
        let content_2 = generate_random_content();
        let header_1 = generate_random_header(&rand_1.into(), &content_1);
        let header_2 = generate_random_header(&rand_1.into(), &content_2);
        let header_3 = generate_random_header(&rand_2.into(), &content_1);

        let block_1 = Block::new(header_1.clone(), content_1.clone());
        let block_2 = Block::new(header_2.clone(), content_1.clone());
        let block_3 = Block::new(header_3.clone(), content_1.clone());
        let block_4 = Block::new(header_1.clone(), content_2.clone());
        let block_5 = Block::new(header_1.clone(), content_1.clone());

        // different header
        assert_ne!(block_1, block_2);
        assert_ne!(block_1, block_3);
        // different content
        assert_ne!(block_1, block_4);
        // same
        assert_eq!(block_1, block_5);
    }

    #[test]
    fn test_get_trans_hashed() {
        let t_1 = generate_random_signed_transaction();
        let t_2 = generate_random_signed_transaction();
        let t_3 = generate_random_signed_transaction();
        let content = Content::new_with_trans(&vec![t_1.clone(), t_2.clone(), t_3.clone()]);
        let res = content.get_trans_hashes();
        assert_eq!(t_1.hash, res[0]);
        assert_eq!(t_2.hash, res[1]);
        assert_eq!(t_3.hash, res[2]);
    }

    #[test]
    fn test_try_generate_state() {
        let key_1 = key_pair::random();
        let addr_1: H160 = digest::digest(&digest::SHA256, key_1.public_key().as_ref()).into();
        let random_h256 = generate_random_hash();
        let signed_coinbase_tran = generate_signed_coinbase_transaction(&key_1);
        let content = Content::new_with_trans(&vec![signed_coinbase_tran.clone()]);
        let header = generate_header(&random_h256, &content, 0, &random_h256);
        let block = Block::new(header, content.clone());
        let new_state = block.try_generate_state(&State::new());
        if let Some(state) = new_state.clone() {
            assert!(state.contains_key(&(signed_coinbase_tran.hash.clone(), 0)));
            let value = state.get(&(signed_coinbase_tran.hash.clone(), 0)).unwrap().clone();
            assert_eq!((COINBASE_REWARD, addr_1.clone()), value);
        } else {
            assert!(false);
        }

        let signed_coinbase_tran_2 = generate_signed_coinbase_transaction(&key_1);
        let content = Content::new_with_trans(&vec![signed_coinbase_tran_2.clone()]);
        let header = generate_header(&random_h256, &content, 0, &random_h256);
        let block = Block::new(header, content.clone());
        let state_2 = block.try_generate_state(&new_state.unwrap());
        if let Some(state) = state_2.clone() {
            assert!(state.contains_key(&(signed_coinbase_tran.hash.clone(), 0)));
            let value = state.get(&(signed_coinbase_tran.hash.clone(), 0)).unwrap().clone();
            assert_eq!((COINBASE_REWARD, addr_1.clone()), value);
            assert!(state.contains_key(&(signed_coinbase_tran_2.hash.clone(), 0)));
            let value = state.get(&(signed_coinbase_tran_2.hash.clone(), 0)).unwrap().clone();
            assert_eq!((COINBASE_REWARD, addr_1.clone()), value);
        } else {
            assert!(false);
        }

        // correct
        let signed_coinbase_tran_3 = generate_signed_coinbase_transaction(&key_1);
        let random_h160 = generate_random_h160();
        let txinput = TxInput {pre_hash: signed_coinbase_tran_2.hash.clone(), index: 0};
        let txoutput_1 = TxOutput {rec_address: random_h160, val: COINBASE_REWARD-1};
        let txoutput_2 = TxOutput {rec_address: random_h160, val: 1};
        let valid_tran = generate_signed_transaction(&key_1, vec![txinput], vec![txoutput_1, txoutput_2]);
        let content = Content::new_with_trans(&vec![signed_coinbase_tran_3.clone(), valid_tran.clone()]);
        let header = generate_header(&random_h256, &content, 0, &random_h256);
        let block = Block::new(header, content.clone());
        let non_state = block.try_generate_state(&state_2.clone().unwrap());
        if let Some(state) = non_state.clone() {
            assert!(!state.contains_key(&(signed_coinbase_tran_2.hash.clone(), 0)));
            assert!(state.contains_key(&(valid_tran.hash.clone(), 0)));
            assert!(state.contains_key(&(valid_tran.hash.clone(), 1)));
            let value = state.get(&(valid_tran.hash.clone(), 0)).unwrap().clone();
            assert_eq!((COINBASE_REWARD-1, random_h160), value);
            let value = state.get(&(valid_tran.hash.clone(), 1)).unwrap().clone();
            assert_eq!((1, random_h160), value);
        } else {
            assert!(false);
        }

        // wrong: output is bigger than input
        let signed_coinbase_tran = generate_signed_coinbase_transaction(&key_1);
        let random_h160 = generate_random_h160();
        let txinput = TxInput {pre_hash: signed_coinbase_tran_2.hash.clone(), index: 0};
        let txoutput = TxOutput {rec_address: random_h160, val: COINBASE_REWARD+1};  // +1
        let invalid_tran = generate_signed_transaction(&key_1, vec![txinput], vec![txoutput]);
        let content = Content::new_with_trans(&vec![signed_coinbase_tran.clone(), invalid_tran.clone()]);
        let header = generate_header(&random_h256, &content, 0, &random_h256);
        let block = Block::new(header, content.clone());
        let non_state = block.try_generate_state(&state_2.clone().unwrap());
        if let Some(_) = non_state {
            assert!(false);
        }

        // wrong public key
        let key_2 = key_pair::random();
        let signed_coinbase_tran = generate_signed_coinbase_transaction(&key_1);
        let random_h160 = generate_random_h160();
        let txinput = TxInput {pre_hash: signed_coinbase_tran_2.hash.clone(), index: 0};
        let txoutput = TxOutput {rec_address: random_h160, val: COINBASE_REWARD};
        let invalid_tran = generate_signed_transaction(&key_2, vec![txinput], vec![txoutput]);  // wrong public key
        let content = Content::new_with_trans(&vec![signed_coinbase_tran.clone(), invalid_tran.clone()]);
        let header = generate_header(&random_h256, &content, 0, &random_h256);
        let block = Block::new(header, content.clone());
        let non_state = block.try_generate_state(&state_2.clone().unwrap());
        if let Some(_) = non_state {
            assert!(false);
        }

        // wrong pre_hash
        let signed_coinbase_tran = generate_signed_coinbase_transaction(&key_1);
        let random_h160 = generate_random_h160();
        let txinput = TxInput {pre_hash: generate_random_hash(), index: 0};
        let txoutput = TxOutput {rec_address: random_h160, val: COINBASE_REWARD};
        let invalid_tran = generate_signed_transaction(&key_1, vec![txinput], vec![txoutput]);
        let content = Content::new_with_trans(&vec![signed_coinbase_tran.clone(), invalid_tran.clone()]);
        let header = generate_header(&random_h256, &content, 0, &random_h256);
        let block = Block::new(header, content.clone());
        let non_state = block.try_generate_state(&state_2.clone().unwrap());
        if let Some(_) = non_state {
            assert!(false);
        }
    }
}
