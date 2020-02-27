use super::hash::{Hashable, H256};
use ring::digest;

/// A Merkle tree.
#[derive(Debug, Default)]
pub struct MerkleTree {
    root: Node,
}

#[derive(Debug, Default)]
pub struct Node {
    hash: H256,
    left: Option<Box<Node>>,
    right: Option<Box<Node>>,
    is_leaf: bool,
    index: usize,
}

impl Node {
    fn new_leaf<T>(data: &T, idx: usize) -> Self where T: Hashable {
        Self {hash: data.hash(), left: None, right: None, is_leaf: true, index: idx}
    }

    fn new_non_leaf(left: Node, right: Node) -> Self {
        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(left.hash.as_ref());
        ctx.update(right.hash.as_ref());
        let h: H256 = ctx.finish().into();
        let i = ((left.index as f32 + right.index as f32)/2.0).ceil() as usize;
        Node {hash: h, left: Some(Box::new(left)), right: Some(Box::new(right)),
                is_leaf: false, index: i}
    }

    fn copy(&self, step: usize) -> Node {
        Node {hash: self.hash.clone(), left: None,
              right: None, is_leaf: true, index: self.index+step}
    }
}

fn ensure_even(nodes: &mut Vec<Node>, step: usize) {
    if nodes.len() % 2 != 0 {
        nodes.push(nodes.last().unwrap().copy(step));
    }
}

fn gen_nodes<T>(data: &[T]) -> Vec<Node> where T: Hashable {
    let mut nodes = Vec::<Node>::new();
    for (i, d) in data.iter().enumerate() {
        nodes.push(Node::new_leaf(d, i));
    }
    nodes
}

impl MerkleTree {
    pub fn new<T>(data: &[T]) -> Self where T: Hashable + Clone, {
        let mut nodes = gen_nodes(data);
        let mut step = 1;
        while nodes.len() > 1 {
            let mut cur = Vec::<Node>::new();
            {
                ensure_even(&mut nodes, step);

                let l = nodes.len();
                let mut c = 0;
                let mut drain = nodes.drain(..);

                while c < l {
                    cur.push(Node::new_non_leaf(drain.next().unwrap(), drain.next().unwrap()));
                    c += 2;
                }
            }
            nodes = cur;
            step *= 2;
        }
        Self {root: nodes.pop().unwrap()}
    }

    pub fn root(&self) -> H256 {
        self.root.hash.into()
    }

    /// Returns the Merkle Proof of data at index i
    pub fn proof(&self, idx: usize) -> Vec<H256> {
        let mut result = Vec::<H256>::new();
        self.trace_proof(idx, &self.root, &mut result);
        result.reverse();
        result
    }

    fn trace_proof(&self, idx: usize, node: &Node, result: &mut Vec<H256>) {
        match *node {
            Node {hash: _, is_leaf: _, index,
                  left: Some(ref left), right: Some(ref right)} => {
                if idx < index {
                    result.push(right.hash.clone());
                    self.trace_proof(idx, left, result);
                } else {
                    result.push(left.hash.clone());
                    self.trace_proof(idx, right, result);
                }
            }
            _ => {}
        }
    }
}

/// Verify that the datum hash with a vector of proofs will produce the Merkle root. Also need the
/// index of datum and `leaf_size`, the total number of leaves.
pub fn verify(root: &H256, datum: &H256, proof: &[H256], index: usize, _leaf_size: usize) -> bool {
    let mut acc_hash = datum.clone();
    let mut bits = index;
    for h in proof.iter() {
        acc_hash.concat_hash(h, bits % 2 == 0);
        bits = bits >> 1;
    }
    acc_hash == *root
}

#[cfg(test)]
mod tests {
    use crate::crypto::hash::H256;
    use super::*;
    use rand::Rng;

    macro_rules! gen_merkle_tree_data {
        () => {{
            vec![
                (hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d")).into(),
                (hex!("0101010101010101010101010101010101010101010101010101010101010202")).into(),
            ]
        }};
    }

    macro_rules! gen_merkle_tree_data_2 {
        () => {{
            vec![
                (hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d")).into(),
                (hex!("0101010101010101010101010101010101010101010101010101010101010202")).into(),
                (hex!("0301010101010101010101010101010101010101010101010101010101010202")).into(),
                (hex!("0401010101010101010101010101010101010101010101010101010101010202")).into(),
            ]
        }};
    }

    macro_rules! gen_merkle_tree_data_3 {
        () => {{
            vec![
                (hex!("000b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d")).into(),
                (hex!("0101010101010101010101010101010101010101010101010101010101010202")).into(),
                (hex!("0201010101010101010101010101010101010101010101010101010101010202")).into(),
                (hex!("0301010101010101010101010101010101010101010101010101010101010202")).into(),
                (hex!("0401010101010101010101010101010101010101010101010101010101010202")).into(),
                (hex!("0501010101010101010101010101010101010101010101010101010101010202")).into(),
                (hex!("0601010101010101010101010101010101010101010101010101010101010202")).into(),
                (hex!("0701010101010101010101010101010101010101010101010101010101010202")).into(),
                (hex!("0801010101010101010101010101010101010101010101010101010101010202")).into(),
                (hex!("0901010101010101010101010101010101010101010101010101010101010202")).into(),
            ]
        }};
    }

    macro_rules! gen_merkle_tree_assignment2 {
        () => {{
            vec![
                (hex!("0000000000000000000000000000000000000000000000000000000000000011")).into(),
                (hex!("0000000000000000000000000000000000000000000000000000000000000022")).into(),
                (hex!("0000000000000000000000000000000000000000000000000000000000000033")).into(),
                (hex!("0000000000000000000000000000000000000000000000000000000000000044")).into(),
                (hex!("0000000000000000000000000000000000000000000000000000000000000055")).into(),
                (hex!("0000000000000000000000000000000000000000000000000000000000000066")).into(),
                (hex!("0000000000000000000000000000000000000000000000000000000000000077")).into(),
                (hex!("0000000000000000000000000000000000000000000000000000000000000088")).into(),
            ]
        }};
    }

    macro_rules! gen_merkle_tree_assignment2_another {
        () => {{
            vec![
                (hex!("1000000000000000000000000000000000000000000000000000000000000088")).into(),
                (hex!("2000000000000000000000000000000000000000000000000000000000000077")).into(),
                (hex!("3000000000000000000000000000000000000000000000000000000000000066")).into(),
                (hex!("4000000000000000000000000000000000000000000000000000000000000055")).into(),
                (hex!("5000000000000000000000000000000000000000000000000000000000000044")).into(),
                (hex!("6000000000000000000000000000000000000000000000000000000000000033")).into(),
                (hex!("7000000000000000000000000000000000000000000000000000000000000022")).into(),
                (hex!("8000000000000000000000000000000000000000000000000000000000000011")).into(),
            ]
        }};
    }

    // "0301010101010101010101010101010101010101010101010101010101010202"
    // ->
    // "a9f93073dfc29e2ad33c994241180db4e91a952f2803b24ab2b655f559b683a0"

    // "0401010101010101010101010101010101010101010101010101010101010202"
    // ->
    // "6722adeb7ac6a5f3008e96a51a18c8c06489e28f7ee0f39633804a982ae5e077"

    // concate the above two ->
    // "95f92a9251eec866f3e32a08cd7edcbfcfb86da23fcdd6eb50789c293c2b8d1a"

    // concate:
    // "6b787718210e0b3b608814e04e61fde06d0df794319a12162f287412df3ec920"
    // and
    // "95f92a9251eec866f3e32a08cd7edcbfcfb86da23fcdd6eb50789c293c2b8d1a"
    // ->
    // "12a38f5e8e70569659512f79885f0b6e8d95b13ebee4a2bfc63a4c6fc6b64d80"

    fn gen_random_h256() -> H256 {
        let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
        random_bytes.into()
    }

    fn gen_random_h256_vec(size: usize) -> Vec<H256> {
        let mut vec = Vec::<H256>::new();
        for _ in 0..size {
            vec.push(gen_random_h256());
        }
        vec
    }

    #[test]
    fn root() {
        let input_data: Vec<H256> = gen_merkle_tree_data!();
        let merkle_tree = MerkleTree::new(&input_data);
        let root = merkle_tree.root();
        assert_eq!(
            root,
            (hex!("6b787718210e0b3b608814e04e61fde06d0df794319a12162f287412df3ec920")).into()
        );
        // "b69566be6e1720872f73651d1851a0eae0060a132cf0f64a0ffaea248de6cba0" is the hash of
        // "0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d"
        // "965b093a75a75895a351786dd7a188515173f6928a8af8c9baa4dcff268a4f0f" is the hash of
        // "0101010101010101010101010101010101010101010101010101010101010202"
        // "6b787718210e0b3b608814e04e61fde06d0df794319a12162f287412df3ec920" is the hash of
        // the concatenation of these two hashes "b69..." and "965..."
        // notice that the order of these two matters

        let input_data: Vec<H256> = gen_merkle_tree_data_2!();
        let merkle_tree = MerkleTree::new(&input_data);
        let root = merkle_tree.root();
        assert_eq!(
            root,
            (hex!("12a38f5e8e70569659512f79885f0b6e8d95b13ebee4a2bfc63a4c6fc6b64d80")).into()
        );
    }

    #[test]
    fn proof() {
        let input_data: Vec<H256> = gen_merkle_tree_data!();
        let merkle_tree = MerkleTree::new(&input_data);
        let proof = merkle_tree.proof(0);
        assert_eq!(proof,
                vec![hex!("965b093a75a75895a351786dd7a188515173f6928a8af8c9baa4dcff268a4f0f").into()]
        );
        // "965b093a75a75895a351786dd7a188515173f6928a8af8c9baa4dcff268a4f0f" is the hash of
        // "0101010101010101010101010101010101010101010101010101010101010202"
        let input_data: Vec<H256> = gen_merkle_tree_data_2!();
        let merkle_tree = MerkleTree::new(&input_data);
        let proof = merkle_tree.proof(0);
        assert_eq!(proof,
                   vec![hex!("965b093a75a75895a351786dd7a188515173f6928a8af8c9baa4dcff268a4f0f").into(),
                        hex!("95f92a9251eec866f3e32a08cd7edcbfcfb86da23fcdd6eb50789c293c2b8d1a").into()]
        );
        let proof = merkle_tree.proof(2);
        assert_eq!(proof,
                vec![hex!("6722adeb7ac6a5f3008e96a51a18c8c06489e28f7ee0f39633804a982ae5e077").into(),
                    hex!("6b787718210e0b3b608814e04e61fde06d0df794319a12162f287412df3ec920").into()]
 );
    }

    #[test]
    fn verifying() {
        let input_data: Vec<H256> = gen_merkle_tree_data!();
        let merkle_tree = MerkleTree::new(&input_data);
        let proof = merkle_tree.proof(0);
        assert!(verify(&merkle_tree.root(), &input_data[0].hash(), &proof, 0, input_data.len()));

        let proof = merkle_tree.proof(1);
        assert!(verify(&merkle_tree.root(), &input_data[1].hash(), &proof, 1, input_data.len()));

        let input_data: Vec<H256> = gen_merkle_tree_data_2!();
        let merkle_tree = MerkleTree::new(&input_data);

        for i in 0..input_data.len() {
            let proof = merkle_tree.proof(i);
            assert!(verify(&merkle_tree.root(), &input_data[i].hash(), &proof, i, input_data.len()));
        }

        let input_data: Vec<H256> = gen_merkle_tree_data_3!();
        let merkle_tree = MerkleTree::new(&input_data);

        for i in 0..input_data.len() {
            let proof = merkle_tree.proof(i);
            assert!(verify(&merkle_tree.root(), &input_data[i].hash(), &proof, i, input_data.len()));
        }

        for size in 1..66 {
            let input_data: Vec<H256> = gen_random_h256_vec(size);
            let merkle_tree = MerkleTree::new(&input_data);

            for i in 0..input_data.len() {
                let proof = merkle_tree.proof(i);
                assert!(verify(&merkle_tree.root(), &input_data[i].hash(), &proof, i, input_data.len()));
            }
        }
    }

    #[test]
    fn test_gen_nodes() {
        let input_data: Vec<H256> = gen_merkle_tree_data_3!();
        let v = gen_nodes(&input_data);
        assert_eq!(input_data.len(), v.len());
        for i in 0..input_data.len() {
            assert_eq!(&input_data[i].hash(), &v[i].hash);
            assert_eq!(&input_data[i].hash(), &v[i].hash);
            assert_eq!(i, v[i].index);
            assert!(v[i].is_leaf);
        }
    }

    #[test]
    fn test_ensure_even() {
        let input_data: Vec<H256> = gen_merkle_tree_data_3!();
        let mut v = gen_nodes(&input_data);
        ensure_even(&mut v, 1);
        assert!(v.len() % 2 == 0);
        v.pop();
        ensure_even(&mut v, 3);
        assert!(v.len() % 2 == 0);
    }

    #[test]
    fn assignment2_merkle_root() {
        let input_data: Vec<H256> = gen_merkle_tree_assignment2!();
        let merkle_tree = MerkleTree::new(&input_data);
        let root = merkle_tree.root();
        assert_eq!(
            root,
            (hex!("6e18c8441bc8b0d1f0d4dc442c0d82ff2b4f38e2d7ca487c92e6db435d820a10")).into()
        );
    }

    #[test]
    fn assignment2_merkle_verify() {
        let input_data: Vec<H256> = gen_merkle_tree_assignment2!();
        let merkle_tree = MerkleTree::new(&input_data);
        for i in 0.. input_data.len() {
            let proof = merkle_tree.proof(i);
            print!("{}", i);
            assert!(verify(&merkle_tree.root(), &input_data[i].hash(), &proof, i, input_data.len()));
        }
        let input_data_2: Vec<H256> = gen_merkle_tree_assignment2_another!();
        let merkle_tree_2 = MerkleTree::new(&input_data_2);
        assert!(!verify(&merkle_tree.root(), &input_data[0].hash(), &merkle_tree_2.proof(0), 0, input_data.len()));
    }

    #[test]
    fn assignment2_merkle_proof() {
        use std::collections::HashSet;
        let input_data: Vec<H256> = gen_merkle_tree_assignment2!();
        let merkle_tree = MerkleTree::new(&input_data);
        let proof = merkle_tree.proof(5);
        let proof: HashSet<H256> = proof.into_iter().collect();
        let p: H256 = (hex!("c8c37c89fcc6ee7f5e8237d2b7ed8c17640c154f8d7751c774719b2b82040c76")).into();
        assert!(proof.contains(&p));
        let p: H256 = (hex!("bada70a695501195fb5ad950a5a41c02c0f9c449a918937267710a0425151b77")).into();
        assert!(proof.contains(&p));
        let p: H256 = (hex!("1e28fb71415f259bd4b0b3b98d67a1240b4f3bed5923aa222c5fdbd97c8fb002")).into();
        assert!(proof.contains(&p));
    }
}
