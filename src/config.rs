use crate::spread::Spreader;

pub static DIFFICULTY: i32 = 17; // number of leading zero

pub static MINING_STEP: u32 = 8192; // number of mining step

pub static BLOCK_SIZE_LIMIT: usize = 256; // size limit of transactions in a block

pub static POOL_SIZE_LIMIT: usize = 100000; // size limit of mempool

pub static TRANSACTION_GENERATE_INTERVAL: u64 = 8000; // time interval(ms) to add a new-created transaction to mempool

pub static TEST_DIF: i32 = 4; // difficulty used for mod test

pub static EASIEST_DIF: i32 = 0; // all-1-difficulty

pub static COINBASE_REWARD: u64 = 50; // reward for miner

pub static RAND_INPUTS_NUM: usize = 4; // number of inputs in generate_random_txinput

pub static RAND_OUTPUTS_NUM: usize = 4; // number of outputs in generate_random_txoutput

pub static VALID_OUTPUTS_NUM: usize = 3; // number of valid tx_outputs in transaction_generator

pub static REPEAT_TEST_TIME: usize = 20; // used for test repeatedly

pub static SPREADER: Spreader = Spreader::Default;