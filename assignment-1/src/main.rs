#[macro_use]
extern crate serde_derive;

use bincode;
use ring::digest;
use hex;

#[derive(Debug, Serialize, Deserialize)]
struct NameHash<'a> {
    name: &'a str,
    hash: &'a str,
}

fn main() {
    let name = "Jun Luo";
    let signature = digest::digest(&digest::SHA256, name.as_bytes());

    let hex_string = hex::encode(signature);

    let name_hash = NameHash {name: &name, hash: &hex_string};
    println!("{:?}", name_hash);

    let encoded: Vec<u8> = bincode::serialize(&name_hash).unwrap();
    println!("{:?}", encoded);

    let decoded: NameHash = bincode::deserialize(&encoded[..]).unwrap();
    println!("{:?}", decoded);
}
