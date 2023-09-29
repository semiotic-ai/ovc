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

}
