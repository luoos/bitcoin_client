use crate::transaction::{SignedTransaction};
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::collections::HashMap;
use crate::crypto::hash::{H160, H256};
use ring::signature::ED25519_PUBLIC_KEY_LEN;

pub fn start_first_timestamp_estimate(transactions: &HashMap<H256, SignedTransaction>,
                                      timestamp_map: &HashMap<H256, Vec<(SocketAddr, i64)>>) -> HashMap<H160, SocketAddr> {
    let mut map_data: HashMap<SignedTransaction, SocketAddr> = HashMap::new();
    for (hash, ip2time) in timestamp_map.iter() {
        let mut earliest = i64::max_value();
        let mut res_ip = SocketAddr::new(
            IpAddr::V4(
                Ipv4Addr::new(127, 0, 0, 1)), 8080);
        for (ip, timestamp) in ip2time.iter() {
            if *timestamp < earliest {
                earliest = *timestamp;
                res_ip = ip.clone();
            }
        }
        if let Some(trans) = transactions.get(hash) {
            map_data.insert(trans.clone(), res_ip.clone());
        }
    }

    estimator(&map_data)
}

pub fn check_right_count(res: &HashMap<H160, SocketAddr>,
                         info_map: &HashMap<H160, (Box<[u8; ED25519_PUBLIC_KEY_LEN]>, u16)>) -> i32 {
    println!("map: {:?}", res);
    println!("answer : {:?}", info_map);
    let mut count = 0;
    for (addr, ip) in info_map {
        if !res.contains_key(addr) {
            continue;
        }
        let estimated_ip = res.get(addr).unwrap();
        if estimated_ip.port() == ip.1 {
            count += 1;
        }
    }
    count
}

pub fn estimator(map_data: &HashMap<SignedTransaction, SocketAddr>) -> HashMap<H160, SocketAddr> {
    // 1. transform Map<Transaction, SocketAddr> to Map<H160, Map<SocketAddr, Integer>>
    let mut input_match_map: HashMap<H160, HashMap<SocketAddr, i32>> = HashMap::new();
//    let mut output_match_map = HashMap::new();
    for (trans, ip) in map_data.iter() {
        let addr: H160 = ring::digest::digest(&ring::digest::SHA256, &trans.public_key).into();
        if let Some(ip2count) = input_match_map.get_mut(&addr) {
            *ip2count.entry(*ip).or_insert(0) += 1;

        } else {
            let mut ip2count = HashMap::new();
            ip2count.insert(ip.clone(), 1);
            input_match_map.insert(addr.clone(), ip2count);
        }

//        for output in trans.transaction.outputs.iter() {
//            let addr = output.rec_address;
//            if output_match_map.contains_key(addr) {
//                let mut ip2count : HashMap<SocketAddr, usize> = output_match_map.get_mut(&addr).unwrap();
//                *ip2count.entry(*ip).or_insert(0) += 1;
//            } else {
//                let mut ip2count = HashMap::new();
//                ip2count.insert(ip.clone(), 1);
//                output_match_map.insert(addr.clone(), ip2count);
//            }
//        }
    }

    // 2. match ip with key
    let mut match_map = HashMap::new();
    for (addr, ip_map) in input_match_map.iter() {
        let mut max_count = 0;
        let mut max_ip = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        for (ip, count) in ip_map.iter() {
            if *count >= max_count {
                max_count = *count;
                max_ip = ip.clone();
            }
        }
        match_map.insert(addr.clone(), max_ip.clone());
    }

    match_map
}

#[cfg(any(test, test_utilities))]
mod tests {
    use crate::helper::generate_random_signed_transaction;
    use crate::network::estimator::{start_first_timestamp_estimate, check_right_count};
    use std::collections::HashMap;
    use std::net::{SocketAddr, IpAddr, Ipv4Addr};
    use crate::crypto::hash::H160;
    use ring::signature::ED25519_PUBLIC_KEY_LEN;

    #[test]
    fn test_ft_estimator() {
        let mut transactions = HashMap::new();
        let mut timestamp_map = HashMap::new();
        let mut answer: HashMap<H160, (Box<[u8; ED25519_PUBLIC_KEY_LEN]>, u16)> = HashMap::new();
        for i in 0..5 {
            let trans = generate_random_signed_transaction();
            transactions.insert(trans.hash.clone(), trans.clone());
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), i);
            timestamp_map.insert(trans.hash.clone(), vec![(addr.clone(), trans.transaction.ts as i64)]);
            let key = ring::digest::digest(&ring::digest::SHA256, &trans.public_key).into();

            let mut pub_key: [u8; ED25519_PUBLIC_KEY_LEN] = [0; ED25519_PUBLIC_KEY_LEN];
            pub_key[..].copy_from_slice(&trans.public_key.clone().as_ref()[..]);
            answer.insert(key, (Box::new(pub_key), i));
        }
        let res = start_first_timestamp_estimate(&transactions, &timestamp_map);
        println!("{:?}", res);
        println!("{:?}", answer.values());
        let precise = check_right_count(&res, &answer);
        assert!(precise == 5);
    }
}