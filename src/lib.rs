use std::{ops::Mul, cell::RefCell, rc::Rc, sync::Arc, error::Error, any::Any};
use ark_bn254::{G1Projective, Fr};
use ark_crypto_primitives::{merkle_tree::{self, ByteDigestConverter, MerkleTree, Config}, crh::{sha256::{Sha256, digest::typenum::Le}, CRHScheme, TwoToOneCRHScheme}};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use hasher::{HasherKeccak, Hasher};
use reth_primitives::{Receipt, rpc_utils::rlp::RlpStream, bytes::BytesMut, ReceiptWithBloomRef, Address};
use ark_ff::fields::field_hashers::{DefaultFieldHasher, HashToField};
use reth_codecs::Compact;
use cita_trie::{node::Node, MemoryDB, PatriciaTrie, Trie};
use reth_rlp::Encodable;
use serde::{Deserialize, Serialize};
use ark_crypto_primitives::crh::sha256::digest::Digest;
use ark_crypto_primitives::merkle_tree::DigestConverter;

#[derive(Clone)]
pub struct OvcProver {
    root: Vec<u8>,
    left_leaves: Vec<Vec<u8>>,
    right_leaves: Vec<Vec<u8>>,
    commit_key: Vec<G1Projective>,
    commitment: G1Projective
}

impl OvcProver {
    fn new(commit_key: Vec<G1Projective>, receipts: Vec<Receipt>) -> OvcProver {
        let hash_receipts_vec: Vec<Fr> = receipts
            .iter()
            .map(|receipt| hash_receipts_vec(receipt))
            .collect();

        let (commitment, tree, leaves) = commit_and_merkle(commit_key.clone(), hash_receipts_vec);
        OvcProver{
            root: tree.root(),
            left_leaves: leaves[0..leaves.len()/2].to_vec(),
            right_leaves: leaves[leaves.len()/2..leaves.len()].to_vec(),
            commit_key,
            commitment
        }
    }

    fn first_response(&mut self) -> (Vec<u8>, Vec<u8>) {
        let left_leaves = self.left_leaves.clone();
        let right_leaves = self.right_leaves.clone();
        let left_tree = Sha256MerkleTree::new(&(), &(), left_leaves.clone()).unwrap();
        let right_tree = Sha256MerkleTree::new(&(), &(), right_leaves.clone()).unwrap();
        
        (left_tree.root(), right_tree.root())
    }

    fn reply_to_verifier_step(&mut self, open_side: &OpenKind) -> (Vec<u8>, Vec<u8>){
        let leaves = match open_side {
            OpenKind::left => self.left_leaves.clone(),
            OpenKind::right => self.right_leaves.clone()
        };

        if leaves.len() == 1 {
            return (leaves[0].clone(), leaves[0].clone())
        }
        let left_leaves = leaves[0..leaves.len()/2].to_vec();
        let right_leaves = leaves[leaves.len()/2..leaves.len()].to_vec();
        assert!(left_leaves.len() == right_leaves.len());
        if left_leaves.len() == 1 {
            let left_leaf_hash = <LeafH as CRHScheme>::evaluate(&(), left_leaves[0].clone()).unwrap();
            let right_leaf_hash = <LeafH as CRHScheme>::evaluate(&(), right_leaves[0].clone()).unwrap();
            self.left_leaves = left_leaves;
            self.right_leaves = right_leaves;
            return (left_leaf_hash, right_leaf_hash)
        } else {
            let left_tree = Sha256MerkleTree::new(&(), &(), left_leaves.clone()).unwrap();
            let right_tree = Sha256MerkleTree::new(&(), &(), right_leaves.clone()).unwrap();
            self.left_leaves = left_leaves;
            self.right_leaves = right_leaves;
            (left_tree.root(), right_tree.root())
        }
        
    }
}

#[derive(Clone)]
pub struct OvcVerifier {
    prover_1_root: Vec<u8>,
    prover_2_root: Vec<u8>,
    tree_size: usize
}

#[derive(Debug, PartialEq)]
pub enum OpenKind {
    left,
    right
}

impl OvcVerifier{
    fn update_roots(mut self, root_1: Vec<u8>, root_2: Vec<u8>) {
        self.prover_1_root = root_1;
        self.prover_2_root = root_2;
        self.tree_size = self.tree_size/2;
    }

    fn find_disagreement_step(&mut self, prover_1_l_child: Vec<u8>, prover_1_r_child: Vec<u8>, prover_2_l_child: Vec<u8>, prover_2_r_child: Vec<u8>) -> OpenKind {
        let mut prover_1_node = Vec::new();
        let mut prover_2_node = Vec::new();
        if self.tree_size == 2 {
            let l_1 = <Sha256MerkleTreeParams as Config>::LeafInnerDigestConverter::convert(prover_1_l_child.clone()).unwrap();
            let r_1 = <Sha256MerkleTreeParams as Config>::LeafInnerDigestConverter::convert(prover_1_r_child.clone()).unwrap();
            let l_2 = <Sha256MerkleTreeParams as Config>::LeafInnerDigestConverter::convert(prover_2_l_child.clone()).unwrap();
            let r_2 = <Sha256MerkleTreeParams as Config>::LeafInnerDigestConverter::convert(prover_2_r_child.clone()).unwrap();
            prover_1_node = <CompressH as TwoToOneCRHScheme>::evaluate(&(), l_1, r_1).unwrap();
            prover_2_node = <CompressH as TwoToOneCRHScheme>::evaluate(&(), l_2, r_2).unwrap();
        }
        else{
            prover_1_node = <CompressH as TwoToOneCRHScheme>::evaluate(&(), prover_1_l_child.clone(), prover_1_r_child.clone()).unwrap();
            prover_2_node = <CompressH as TwoToOneCRHScheme>::evaluate(&(), prover_2_l_child.clone(), prover_2_r_child.clone()).unwrap();
        }
        assert_eq!(prover_1_node, self.prover_1_root);
        assert_eq!(prover_2_node, self.prover_2_root);
        if prover_1_l_child == prover_2_l_child {
            self.prover_1_root = prover_1_r_child;
            self.prover_2_root = prover_2_r_child;
            self.tree_size = self.tree_size/2;
            return OpenKind::right
        }

        else if prover_1_r_child == prover_2_r_child {
            self.prover_1_root = prover_1_l_child;
            self.prover_2_root = prover_2_l_child;
            self.tree_size = self.tree_size/2;
            return OpenKind::left
        }

        else {
            panic!("Provers disagree on the tree")
        }
    }
}
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

pub fn commit_and_merkle(commit_key: Vec<G1Projective>, hashed_logs_vec: Vec<Fr>) -> (G1Projective, Sha256MerkleTree, Vec<Vec<u8>>)
{
    let (unrolled_commitment, commitment) = commit_unrolled(commit_key.clone(), hashed_logs_vec.clone());
    let mut unrolled_commitment_serialized= Vec::new();
    for uc in unrolled_commitment.iter() {
        let mut compressed_bytes = Vec::new();
        uc.serialize_compressed(&mut compressed_bytes).unwrap();
        unrolled_commitment_serialized.push(compressed_bytes);
    }
    let merkle_tree = Sha256MerkleTree::new(&(), &(), unrolled_commitment_serialized.clone()).unwrap();

    (commitment, merkle_tree, unrolled_commitment_serialized)
}

// Compute the hash of a Receipt
pub fn hash_receipts_vec(receipt: &Receipt) -> Fr
{   let mut receipt_bytes = Vec::new();
    receipt.clone().to_compact(&mut receipt_bytes);
    let hasher = <DefaultFieldHasher<Sha256> as HashToField<Fr>>::new(&[1]);
    hasher.hash_to_field(receipt_bytes.as_slice(), 1)[0]
}

// Build a Merkle-Patricia trie from Receipts
pub fn build_from_receipts(receipts: Vec<Receipt>) -> PatriciaTrie<MemoryDB, HasherKeccak> {
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

    trie
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

        // Read receipts and commit
        let receipts_json = std::fs::read("receipts_full.json").unwrap();
        let receipts: Vec<Receipt> = serde_json::from_slice(receipts_json.as_slice()).unwrap();
        let mut hashed_logs_vec = Vec::new();
        for idx in 0..8 {
            hashed_logs_vec.push(hash_receipts_vec(&receipts[idx]));
        }

        // Compute Merkle tree
        let (_commitment, merkle_tree, _) = commit_and_merkle(commit_key.clone(), hashed_logs_vec.clone());

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
    
        let mut trie = build_from_receipts(receipts);
    
        let root = trie.root().unwrap();
        println!("root: {:?}", root);
    
    }

    #[test]
    fn test_inclusion_proof() {
        let receipts_json = std::fs::read("receipts_full.json").unwrap();
        let receipts: Vec<Receipt> = serde_json::from_slice(receipts_json.as_slice()).unwrap();

        let mut trie = build_from_receipts(receipts.clone());
        let key = 1;
        let proof = trie.get_proof(&[key]).unwrap();
        let root = trie.root().unwrap();
        assert!(trie.verify_proof(root.as_slice(), &[key], proof).is_ok());
        
        let test_receipt = receipts[key as usize].clone();
        let bloom_receipt = ReceiptWithBloomRef::from(&test_receipt);
        let mut value_buf = BytesMut::new();
        bloom_receipt.encode_inner(&mut value_buf, false);

        assert_eq!(trie.get(&[key]).unwrap(), Some(value_buf.to_vec()));
    }

    // Test OvcProver and OvcVerifier
    #[test]
    fn test_ovc() {
        let log_num_receipts = 6;
        let num_receipts = 2usize.pow(log_num_receipts);
        let diff_idx = 42;
        // Generate random vector of G1Projective
        let mut rng = ark_std::test_rng();
        let mut commit_key: Vec<G1Projective> = Vec::new();
        for _ in 0..num_receipts {
            commit_key.push(G1Projective::rand(&mut rng));
        }

        // Read receipts and commit
        let receipts_json = std::fs::read("receipts_full.json").unwrap();
        let receipts: Vec<Receipt> = serde_json::from_slice(receipts_json.as_slice()).unwrap();
        let mut hashed_logs_vec = Vec::new();
        for idx in 0..num_receipts {
            hashed_logs_vec.push(hash_receipts_vec(&receipts[idx]));
        }

        // Compute Merkle tree
        let (commitment, merkle_tree, unrolled_commits) = commit_and_merkle(commit_key.clone(), hashed_logs_vec.clone());

        // Generate proof
        let key = diff_idx;
        let inclusion_proof = merkle_tree.generate_proof(key).unwrap();
        let root = merkle_tree.root();
        let mut test_bytes = Vec::new();
        commit_key[key].mul(hashed_logs_vec[key]).serialize_compressed(&mut test_bytes).unwrap();

        // Verify proof
        assert!(inclusion_proof.verify(&(), &(), &root, test_bytes).unwrap());

        // Generate proof for OVC
        let mut ovc_prover_1 = OvcProver::new(commit_key.clone(), receipts[0..num_receipts].to_vec());
        let mut receipts_2 = receipts.clone();
        receipts_2[diff_idx] = receipts_2[6].clone();
        let mut ovc_prover_2 = OvcProver::new(commit_key, receipts_2[0..num_receipts].to_vec());
        
        let mut ovc_verifier = OvcVerifier{
                prover_1_root: ovc_prover_1.clone().root,
                prover_2_root: ovc_prover_2.clone().root,
                tree_size: num_receipts,
            };
        
        let mut prover_1_response = ovc_prover_1.first_response();
        let mut prover_2_response = ovc_prover_2.first_response();

        for _ in 0..log_num_receipts {
            let verifier_request = ovc_verifier.find_disagreement_step(prover_1_response.0, prover_1_response.1, prover_2_response.0, prover_2_response.1);
            prover_1_response = ovc_prover_1.reply_to_verifier_step(&verifier_request);
            prover_2_response = ovc_prover_2.reply_to_verifier_step(&verifier_request);
        }
        assert_eq!(prover_1_response.0, prover_1_response.1);
        assert_eq!(prover_2_response.0, prover_2_response.1);

        assert_eq!(prover_1_response.0, unrolled_commits[diff_idx]);
        assert_ne!(prover_2_response.0, unrolled_commits[diff_idx]);
    }

}
