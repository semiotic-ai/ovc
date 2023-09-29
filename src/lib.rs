use std::{ops::Mul, cell::RefCell, rc::Rc, sync::Arc};
use ark_bn254::{G1Projective, Fr};
use ark_crypto_primitives::{merkle_tree::{self, ByteDigestConverter, MerkleTree, Config}, crh::{sha256::Sha256, CRHScheme, TwoToOneCRHScheme}};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use hasher::HasherKeccak;
use reth_primitives::{Receipt, rpc_utils::rlp::RlpStream, bytes::BytesMut, ReceiptWithBloomRef};
use ark_ff::fields::field_hashers::{DefaultFieldHasher, HashToField};
use reth_codecs::Compact;
use cita_trie::{node::Node, MemoryDB, PatriciaTrie, Trie};
use reth_rlp::Encodable;
use serde::{Deserialize, Serialize};


pub fn commit_unrolled(commit_key: Vec<G1Projective>, hashed_logs_vec: Vec<Fr>) -> (Vec<G1Projective>, G1Projective)
{
    let unrolled_commitment: Vec<G1Projective> = commit_key.iter().zip(hashed_logs_vec).map(|(g, l)| g.mul(l)).collect();
    let commitment = unrolled_commitment.iter().sum();

    (unrolled_commitment, commitment)
}


type LeafH = Sha256;
type CompressH = Sha256;

struct Sha256MerkleTreeParams;

impl Config for Sha256MerkleTreeParams {
    type Leaf = [u8];

    type LeafDigest = <LeafH as CRHScheme>::Output;
    type LeafInnerDigestConverter = ByteDigestConverter<Self::LeafDigest>;
    type InnerDigest = <CompressH as TwoToOneCRHScheme>::Output;

    type LeafHash = LeafH;
    type TwoToOneHash = CompressH;
}
type Sha256MerkleTree = MerkleTree<Sha256MerkleTreeParams>;

pub fn commit_and_merkle(commit_key: Vec<G1Projective>, hashed_logs_vec: Vec<Fr>) -> (G1Projective, Sha256MerkleTree)
{
    let (unrolled_commitment, commitment) = commit_unrolled(commit_key.clone(), hashed_logs_vec.clone());
    let mut unrolled_commitment_serialized= Vec::new();
    for uc in unrolled_commitment.iter() {
        let mut compressed_bytes = Vec::new();
        uc.serialize_compressed(&mut compressed_bytes).unwrap();
        unrolled_commitment_serialized.push(compressed_bytes);
    }
    let merkle_tree = Sha256MerkleTree::new(&(), &(), unrolled_commitment_serialized.clone()).unwrap();

    (commitment, merkle_tree)
}

// Compute the hash of a Receipt
pub fn hash_receipts_vec(receipt: &Receipt) -> Fr
{   let mut receipt_bytes = Vec::new();
    receipt.clone().to_compact(&mut receipt_bytes);
    let hasher = <DefaultFieldHasher<Sha256> as HashToField<Fr>>::new(&[1]);
    hasher.hash_to_field(receipt_bytes.as_slice(), 1)[0]
}

// Open a commitment to an event log and prove inclusion in an Ethereum block header

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncodedTrie {
    pub root: Vec<u8>,
    pub trie: Vec<Vec<usize>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Inputs {
    pub trie: EncodedTrie,
}

pub fn build_from_receipts(receipts: Vec<Receipt>) -> EncodedTrie {
    let memdb = Arc::new(MemoryDB::new(true));
    let hasher = Arc::new(HasherKeccak::new());

    let mut trie = PatriciaTrie::new(memdb.clone(), hasher.clone());
    let mut key_buf = BytesMut::new();
    let mut value_buf = BytesMut::new();

    for (idx, receipt) in receipts.iter().enumerate() {
        key_buf.clear();
        idx.encode(&mut key_buf);

        value_buf.clear();
        let bloom_receipt = ReceiptWithBloomRef::from(receipt);
        bloom_receipt.encode_inner(&mut value_buf, false);
        trie.insert(key_buf.to_vec(), value_buf.to_vec()).unwrap();
    }

    let trie_vec = Rc::new(RefCell::new(Vec::new()));
    
    let root_node = trie.root.clone();
    encode_trie_rec(root_node, trie_vec.clone());
    let root = trie.root().unwrap();
    trie_vec.borrow_mut().reverse();

    EncodedTrie {
        root,
        trie: Rc::try_unwrap(trie_vec).unwrap().into_inner(),
    }
}

fn encode_trie_rec(root: Node, state: Rc<RefCell<Vec<Vec<usize>>>>) -> usize {
    match root {
        Node::Branch(branch) => {
            let borrow_branch = branch.borrow();

            if borrow_branch.value.is_some() {
                panic!("unexpected branch node with value");
            }

            let mut children = Vec::new();
            for i in 0..16 {
                let child = borrow_branch.children[i].clone();

                let child_idx = encode_trie_rec(child, state.clone());
                children.push(child_idx);
            }

            let mut state_inner = state.borrow_mut();
            state_inner.push(children);
            state_inner.len()
        }
        Node::Leaf(leaf) => {
            let borrow_leaf = leaf.borrow();

            let mut stream = RlpStream::new_list(2);
            stream.append(&borrow_leaf.key.encode_compact());
            stream.append(&borrow_leaf.value);

            let buf = stream.out().to_vec();
            let buf = buf
                .iter()
                .cloned()
                .map(|e| e as usize)
                .collect::<Vec<usize>>();

            let mut state_inner = state.borrow_mut();
            state_inner.push(buf);
            state_inner.len()
        }
        Node::Empty => 0,
        _ => {
            panic!("unexpected node type");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::{VariableBaseMSM, CurveGroup};
    use ark_std::{self, UniformRand};
    use ark_bn254::G1Projective as G;
    use serde_json;
    

    // Test commit_unrolled
    // Use randomly generated vector of G1Projective and Fr
    #[test]
    fn test_commit_unrolled(){
        // Generate random vector of G1Projective
        let mut rng = ark_std::test_rng();
        let mut commit_key: Vec<G1Projective> = Vec::new();
        for _ in 0..10 {
            commit_key.push(G1Projective::rand(&mut rng));
        }

        // Generate random vector of Fr
        let mut hashed_logs_vec: Vec<Fr> = Vec::new();
        for _ in 0..10 {
            hashed_logs_vec.push(Fr::rand(&mut rng));
        }

        // Compute unrolled commitment
        let (unrolled_commitment, commitment) = commit_unrolled(commit_key.clone(), hashed_logs_vec.clone());

        // Check length of unrolled commitment
        assert_eq!(unrolled_commitment.len(), 10);

        // Check that commitment equals expected value
        let commit_key_affine = commit_key.iter().map(|g| g.into_affine()).collect::<Vec<_>>();
        let expected_commitment = G::msm(commit_key_affine.as_slice(), hashed_logs_vec.as_slice()).unwrap();
        assert_eq!(commitment.into_affine(), expected_commitment);

        // Check that unrolled commitment values are as expected
        let expected_commitment_5 =  commit_key[5].mul(hashed_logs_vec[5]); 
        assert_eq!(unrolled_commitment[5], expected_commitment_5);
    }

    // Test commit_and_merkle
    // Use randomly generated vector of G1Projective and Fr
    #[test]
    fn test_commit_and_merkle(){
        // Generate random vector of G1Projective
        let mut rng = ark_std::test_rng();
        let mut commit_key: Vec<G1Projective> = Vec::new();
        for _ in 0..8 {
            commit_key.push(G1Projective::rand(&mut rng));
        }

        // Generate random vector of Fr
        let mut hashed_logs_vec: Vec<Fr> = Vec::new();
        for _ in 0..8 {
            hashed_logs_vec.push(Fr::rand(&mut rng));
        }

        // Compute Merkle tree
        let (_commitment, merkle_tree) = commit_and_merkle(commit_key.clone(), hashed_logs_vec.clone());

        // Check inclusion proof
        let mut test_bytes = Vec::new();
        commit_key[5].mul(hashed_logs_vec[5]).serialize_compressed(&mut test_bytes).unwrap();
        let inclusion_proof = merkle_tree.generate_proof(5).unwrap();
        let root = merkle_tree.root();
        assert!(inclusion_proof.verify(&(), &(), &root, test_bytes).unwrap());

    }

    #[test]
    fn test_build_from_receipts() {
        let receipts_json = std::fs::read("receipts_full.json").unwrap();
        let receipts: Vec<Receipt> = serde_json::from_slice(receipts_json.as_slice()).unwrap();
    
        let trie = build_from_receipts(receipts);
    
        let root = trie.root.clone();
        println!("root: {:?}", root);
    
    }

}
