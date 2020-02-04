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
    fn leftNode(&self) -> Result<&Node, &'static str> {
        match self.left {
            Some(ref x) => Ok(x),
            None => Err("No left child"),
        }
    }

    fn rightNode(&self) -> Result<&Node, &'static str> {
        match self.right {
            Some(ref x) => Ok(x),
            None => Err("No right child"),
        }
    }
}

fn get_split_index(l: usize) -> usize {
    let i = (l as f64).log2();
    let i = (i.ceil() as u32) - 1;
    2u32.pow(i) as usize
}

fn generate_node<T>(data: &[T], offset: usize) -> Node where T: Hashable {
    if data.len() == 1 {
        Node {hash: data[0].hash(), left: None, right: None,
              is_leaf: true, index: offset}
    } else {
        let i = get_split_index(data.len());
        let left = generate_node(&data[..i], offset);
        let right = generate_node(&data[i..], offset+i);
        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(left.hash.as_ref());
        ctx.update(right.hash.as_ref());
        let h: H256 = ctx.finish().into();
        Node {hash: h, left: Some(Box::new(left)), right: Some(Box::new(right)),
              is_leaf: false, index: offset+i}
    }
}

impl MerkleTree {
    pub fn new<T>(data: &[T]) -> Self where T: Hashable + Clone, {
        let mut copy = data.to_vec();
        if copy.len() > 0 && copy.len() % 2 != 0 {  // odd, duplicate last item
            copy.push(copy.last().unwrap().clone());
        }
        let root = generate_node(&copy, 0);
        Self {root: root}
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
            let left:  &Node = node.leftNode().unwrap();
            let right: &Node = node.rightNode().unwrap();
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
pub fn verify(root: &H256, datum: &H256, proof: &[H256], index: usize, leaf_size: usize) -> bool {
    let mut acc_hash = datum.clone();
    for h in proof.iter() {
        acc_hash.concat_hash(h);
    }
    acc_hash == *root
}

#[cfg(test)]
mod tests {
    use crate::crypto::hash::H256;
    use super::*;

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
    }

    #[test]
    fn split_index() {
        assert_eq!(8, get_split_index(9));
        assert_eq!(4, get_split_index(8));
        assert_eq!(4, get_split_index(7));
        assert_eq!(4, get_split_index(6));
        assert_eq!(4, get_split_index(5));
        assert_eq!(2, get_split_index(3));
        assert_eq!(2, get_split_index(4));
        assert_eq!(1, get_split_index(2));
    }
}
