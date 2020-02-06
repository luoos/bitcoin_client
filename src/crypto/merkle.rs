use super::hash::{Hashable, H256};
use ring::digest;

/// A Merkle tree.
#[derive(Debug, Default)]
pub struct MerkleTree {
    root: Node,
}

#[derive(Debug, Default, Clone)]
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

    fn left_node(&self) -> Result<&Node, &'static str> {
        match self.left {
            Some(ref x) => Ok(x),
            None => Err("No left child"),
        }
    }

    fn right_node(&self) -> Result<&Node, &'static str> {
        match self.right {
            Some(ref x) => Ok(x),
            None => Err("No right child"),
        }
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
    pub fn proof(&self, index: usize) -> Vec<H256> {
        let mut result = Vec::<H256>::new();
        self.trace_proof(index, &self.root, &mut result);
        result.reverse();
        result
    }

    fn trace_proof(&self, index: usize, node: &Node, result: &mut Vec<H256>) {
        if !node.is_leaf {
            let left:  &Node = node.left_node().unwrap();
            let right: &Node = node.right_node().unwrap();
            if index < node.index {
                result.push(right.hash.clone());
                self.trace_proof(index, left, result)
            } else {
                result.push(left.hash.clone());
                self.trace_proof(index, right, result)
            }
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
}
