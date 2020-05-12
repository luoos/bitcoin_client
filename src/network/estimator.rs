use crate::transaction::{SignedTransaction};
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::collections::HashMap;
use crate::crypto::hash::{H160, H256};
use ring::signature::ED25519_PUBLIC_KEY_LEN;

pub fn start_first_timestamp_estimate(transactions: &HashMap<H256, SignedTransaction>,
                                      timestamp_map: &HashMap<H256, Vec<(SocketAddr, i64)>>,
                                      info_map: &HashMap<H160, (Box<[u8; ED25519_PUBLIC_KEY_LEN]>, u16)>,
                                      n : u64)
                                      -> (f64, f64) {
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

    estimator(&map_data, &info_map, n)
}

pub fn check_right_count(res: &HashMap<H160, SocketAddr>,
                         info_map: &HashMap<H160, (Box<[u8; ED25519_PUBLIC_KEY_LEN]>, u16)>) -> i32 {
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

pub fn estimator(map_data: &HashMap<SignedTransaction, SocketAddr>,
                 info_map: &HashMap<H160, (Box<[u8; ED25519_PUBLIC_KEY_LEN]>, u16)>,
                 n : u64) -> (f64, f64) {
    // transform Map<Transaction, SocketAddr> to Map<H160, Map<SocketAddr, Integer>>
    let mut input_match_map: HashMap<H160, HashMap<SocketAddr, i32>> = HashMap::new();
    for (trans, ip) in map_data.iter() {
        let addr: H160 = ring::digest::digest(&ring::digest::SHA256, &trans.public_key).into();
        if let Some(ip2count) = input_match_map.get_mut(&addr) {
            *ip2count.entry(*ip).or_insert(0) += 1;
        } else {
            let mut ip2count = HashMap::new();
            ip2count.insert(ip.clone(), 1);
            input_match_map.insert(addr.clone(), ip2count);
        }
    }

    // match ip with key
    let mut precision_count = HashMap::new();
    let mut precision_sum = HashMap::new();
    let mut final_recall = 0.;
    for (addr, ip_map) in input_match_map.iter() {
        let mut sum_count = 0;
        let mut map_count = 0;
        for (ip, count) in ip_map.iter() {
            if let Some(ans_ip) = info_map.get(addr) {
                if ans_ip.1 == ip.port() {
                    map_count = *count;
                    // update precision
                    precision_count.insert(ip.port(), *count);
                }
            }
            // update precision sum
            if let Some(ip_sum) = precision_sum.get_mut(&ip.port()) {
                *ip_sum += count;
            } else {
                precision_sum.insert(ip.port(), *count);
            }
            sum_count += *count;
        }
        final_recall += map_count as f64/ sum_count as f64;
    }
    final_recall /= n as f64;

    let mut final_precision = 0.;
    for (ip, count) in precision_count {
        final_precision += count as f64 / *precision_sum.get(&ip).unwrap() as f64;
    }
    final_precision /= n as f64;
    (final_recall, final_precision)
}

#[cfg(any(test, test_utilities))]
mod tests {
    use crate::helper::generate_random_signed_transaction;
    use crate::network::estimator::{start_first_timestamp_estimate};
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
        let res = start_first_timestamp_estimate(&transactions, &timestamp_map, &answer, 1);
        println!("{:?}", res);
        println!("{:?}", answer.values());
        assert!(res.1 == 5.);
    }
}


