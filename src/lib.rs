use ark_bn254::{Fr, G1Projective};
use ark_crypto_primitives::merkle_tree::{DigestConverter};
use ark_crypto_primitives::{
    crh::{sha256::Sha256, CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{ByteDigestConverter, Config, MerkleTree},
};
use ark_ff::fields::field_hashers::{DefaultFieldHasher, HashToField};
use ark_serialize::CanonicalSerialize;
use cita_trie::{MemoryDB, PatriciaTrie, Trie, verify_proof};
use hasher::HasherKeccak;
use reth_codecs::Compact;
use reth_primitives::{bytes::BytesMut, Receipt, ReceiptWithBloomRef};
use reth_rlp::Encodable;
use std::{ops::Mul, sync::Arc};

#[derive(Clone)]
struct OvcProver {
    root: Vec<u8>,
    left_leaves: Vec<Vec<u8>>,
    right_leaves: Vec<Vec<u8>>,
    commit_key: Vec<G1Projective>,
    commitment: G1Projective,
    disagreement_idx: usize,
}

pub struct StepResponse {
    pub left: Vec<u8>,
    pub right: Vec<u8>,
}

pub enum Response {
    StepResponse{
        left: Vec<u8>,
        right: Vec<u8>,
    },
    Leaf(Vec<u8>),
}

impl OvcProver {
    pub fn new(commit_key: Vec<G1Projective>, receipts: Vec<Receipt>) -> OvcProver {
        let hash_receipts_vec: Vec<Fr> = receipts
            .iter()
            .map(|receipt| hash_receipts_vec(receipt))
            .collect();

        let (commitment, tree, leaves) = commit_and_merkle(commit_key.clone(), hash_receipts_vec);
        OvcProver {
            root: tree.root(),
            left_leaves: leaves[0..leaves.len() / 2].to_vec(),
            right_leaves: leaves[leaves.len() / 2..leaves.len()].to_vec(),
            commit_key,
            commitment,
            disagreement_idx: 0,
        }
    }

    fn first_response(&mut self) -> StepResponse {
        let left_leaves = self.left_leaves.clone();
        let right_leaves = self.right_leaves.clone();
        let left_tree = Sha256MerkleTree::new(&(), &(), left_leaves.clone()).unwrap();
        let right_tree = Sha256MerkleTree::new(&(), &(), right_leaves.clone()).unwrap();

        StepResponse{left: left_tree.root(), right: right_tree.root()}
    }

    fn reply_to_verifier_step(&mut self, open_side: &OpenKind) -> Response {
        let leaves = match open_side {
            OpenKind::left => self.left_leaves.clone(),
            OpenKind::right => self.right_leaves.clone(),
        };
        self.disagreement_idx = 2*self.disagreement_idx + match open_side {
            OpenKind::left => 0,
            OpenKind::right => 1,
        };

        if leaves.len() == 1 {
            return Response::Leaf(leaves[0].clone());
        }
        let left_leaves = leaves[0..leaves.len() / 2].to_vec();
        let right_leaves = leaves[leaves.len() / 2..leaves.len()].to_vec();
        assert!(left_leaves.len() == right_leaves.len());
        if left_leaves.len() == 1 {
            let left_leaf_hash =
                <LeafH as CRHScheme>::evaluate(&(), left_leaves[0].clone()).unwrap();
            let right_leaf_hash =
                <LeafH as CRHScheme>::evaluate(&(), right_leaves[0].clone()).unwrap();
            self.left_leaves = left_leaves;
            self.right_leaves = right_leaves;
            return Response::StepResponse{left: left_leaf_hash, right: right_leaf_hash};
        } else {
            let left_tree = Sha256MerkleTree::new(&(), &(), left_leaves.clone()).unwrap();
            let right_tree = Sha256MerkleTree::new(&(), &(), right_leaves.clone()).unwrap();
            self.left_leaves = left_leaves;
            self.right_leaves = right_leaves;
            Response::StepResponse{left: left_tree.root(), right: right_tree.root()}
        }
    }

    fn compute_opening_proof(self, receipt_trie: &PatriciaTrie<MemoryDB, HasherKeccak>, receipt: Receipt) -> OpeningProof {
        let mut disagreement_idx_buf = BytesMut::new();
        self.disagreement_idx.encode(&mut disagreement_idx_buf);
        let inclusion_proof = receipt_trie.get_proof(&disagreement_idx_buf).unwrap();
        OpeningProof { receipt, inclusion_proof }
    }
}

#[derive(Clone)]
struct OvcVerifier {
    prover_1_root: Vec<u8>,
    prover_2_root: Vec<u8>,
    tree_size: usize,
    commitment_key: Vec<G1Projective>,
}

#[derive(Debug, PartialEq)]
pub enum OpenKind {
    left,
    right,
}

#[derive(Debug, PartialEq)]
pub enum Winner {
    Both,
    Prover1,
    Prover2,
    Neither
}

pub struct OpeningProof {
    pub receipt: Receipt,
    pub inclusion_proof: Vec<Vec<u8>>,
}

impl OvcVerifier {
    fn update_roots(mut self, root_1: Vec<u8>, root_2: Vec<u8>) {
        self.prover_1_root = root_1;
        self.prover_2_root = root_2;
        self.tree_size = self.tree_size / 2;
    }

    fn find_disagreement_step(
        &mut self,
        prover_1_l_child: Vec<u8>,
        prover_1_r_child: Vec<u8>,
        prover_2_l_child: Vec<u8>,
        prover_2_r_child: Vec<u8>,
    ) -> OpenKind {
        let mut prover_1_node = Vec::new();
        let mut prover_2_node = Vec::new();
        if self.tree_size == 2 {
            let l_1 = <Sha256MerkleTreeParams as Config>::LeafInnerDigestConverter::convert(
                prover_1_l_child.clone(),
            )
            .unwrap();
            let r_1 = <Sha256MerkleTreeParams as Config>::LeafInnerDigestConverter::convert(
                prover_1_r_child.clone(),
            )
            .unwrap();
            let l_2 = <Sha256MerkleTreeParams as Config>::LeafInnerDigestConverter::convert(
                prover_2_l_child.clone(),
            )
            .unwrap();
            let r_2 = <Sha256MerkleTreeParams as Config>::LeafInnerDigestConverter::convert(
                prover_2_r_child.clone(),
            )
            .unwrap();
            prover_1_node = <CompressH as TwoToOneCRHScheme>::evaluate(&(), l_1, r_1).unwrap();
            prover_2_node = <CompressH as TwoToOneCRHScheme>::evaluate(&(), l_2, r_2).unwrap();
        } else {
            prover_1_node = <CompressH as TwoToOneCRHScheme>::evaluate(
                &(),
                prover_1_l_child.clone(),
                prover_1_r_child.clone(),
            )
            .unwrap();
            prover_2_node = <CompressH as TwoToOneCRHScheme>::evaluate(
                &(),
                prover_2_l_child.clone(),
                prover_2_r_child.clone(),
            )
            .unwrap();
        }
        assert_eq!(prover_1_node, self.prover_1_root);
        assert_eq!(prover_2_node, self.prover_2_root);
        if prover_1_l_child != prover_2_l_child {
            self.prover_1_root = prover_1_l_child;
            self.prover_2_root = prover_2_l_child;
            self.tree_size = self.tree_size / 2;
            return OpenKind::left;
        } else {
            self.prover_1_root = prover_1_r_child;
            self.prover_2_root = prover_2_r_child;
            self.tree_size = self.tree_size / 2;
            return OpenKind::right;
        } 
    }


    fn final_check(&self, disagreement_idx: usize, proof_1: OpeningProof, root_1_hash: <CompressH as TwoToOneCRHScheme>::Output, proof_2: OpeningProof, root_2_hash: <CompressH as TwoToOneCRHScheme>::Output) -> Winner { 
        // Hash each receipt to field element.
        let hashed_receipt_1 = hash_receipts_vec(&proof_1.receipt);
        let hashed_receipt_2 = hash_receipts_vec(&proof_2.receipt);

        // Compute commitment at disagreement_idx for each hashed receipt.
        let commitment_1 = self.commitment_key[disagreement_idx].mul(hashed_receipt_1);
        let mut serialized_commitment_1_bytes = Vec::new();
        commitment_1.serialize_compressed(&mut serialized_commitment_1_bytes).unwrap();

        let commitment_2 = self.commitment_key[disagreement_idx].mul(hashed_receipt_2);
        let mut serialized_commitment_2_bytes = Vec::new();
        commitment_2.serialize_compressed(&mut serialized_commitment_2_bytes).unwrap();

        // Check that each inclusion proof is valid with computed commitment.
        let mut prover_1_passed = false;
        let mut disagreement_idx_buf = BytesMut::new();
        disagreement_idx.encode(&mut disagreement_idx_buf);
        let hasher = HasherKeccak::new();
        let valid_proof_1 = verify_proof(&root_1_hash, &disagreement_idx_buf, proof_1.inclusion_proof, hasher);
        if valid_proof_1.is_ok() {
            prover_1_passed = true;
        }

        let mut prover_2_passed = false;
        let hasher = HasherKeccak::new();
        let valid_proof_2 = verify_proof(&root_2_hash, &disagreement_idx_buf, proof_2.inclusion_proof, hasher);
        if valid_proof_2.is_ok(){
            prover_2_passed = true;
        }

        if prover_1_passed && prover_2_passed {
            // TODO: Add logic to determine which receipt is earlier.
            return Winner::Both;
        } else if prover_1_passed && !prover_2_passed {
            return Winner::Prover1;
        } else if !prover_1_passed && prover_2_passed {
            return Winner::Prover2;
        } else {
            return Winner::Neither;
        }
    }
}

pub fn commit_unrolled(
    commit_key: Vec<G1Projective>,
    hashed_logs_vec: Vec<Fr>,
) -> (Vec<G1Projective>, G1Projective) {
    let unrolled_commitment: Vec<G1Projective> = commit_key
        .iter()
        .zip(hashed_logs_vec)
        .map(|(g, l)| g.mul(l))
        .collect();
    let commitment = unrolled_commitment.iter().sum();

    (unrolled_commitment, commitment)
}

type LeafH = Sha256;
type CompressH = Sha256;

pub struct Sha256MerkleTreeParams;

impl Config for Sha256MerkleTreeParams {
    type Leaf = [u8];

    type LeafDigest = <LeafH as CRHScheme>::Output;
    type LeafInnerDigestConverter = ByteDigestConverter<Self::LeafDigest>;
    type InnerDigest = <CompressH as TwoToOneCRHScheme>::Output;

    type LeafHash = LeafH;
    type TwoToOneHash = CompressH;
}
type Sha256MerkleTree = MerkleTree<Sha256MerkleTreeParams>;

pub fn commit_and_merkle(
    commit_key: Vec<G1Projective>,
    hashed_logs_vec: Vec<Fr>,
) -> (G1Projective, Sha256MerkleTree, Vec<Vec<u8>>) {
    let (unrolled_commitment, commitment) =
        commit_unrolled(commit_key.clone(), hashed_logs_vec.clone());
    let mut unrolled_commitment_serialized = Vec::new();
    for uc in unrolled_commitment.iter() {
        let mut compressed_bytes = Vec::new();
        uc.serialize_compressed(&mut compressed_bytes).unwrap();
        unrolled_commitment_serialized.push(compressed_bytes);
    }
    let merkle_tree =
        Sha256MerkleTree::new(&(), &(), unrolled_commitment_serialized.clone()).unwrap();

    (commitment, merkle_tree, unrolled_commitment_serialized)
}

// Compute the hash of a Receipt
pub fn hash_receipts_vec(receipt: &Receipt) -> Fr {
    let mut receipt_bytes = Vec::new();
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
    use ark_bn254::G1Projective as G;
    use ark_ec::{CurveGroup, VariableBaseMSM};
    use ark_std::{self, UniformRand};
    use serde_json;

    // Test commit_unrolled
    // Use randomly generated vector of G1Projective and Fr
    #[test]
    fn test_commit_unrolled() {
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
        let (unrolled_commitment, commitment) =
            commit_unrolled(commit_key.clone(), hashed_logs_vec.clone());

        // Check length of unrolled commitment
        assert_eq!(unrolled_commitment.len(), 10);

        // Check that commitment equals expected value
        let commit_key_affine = commit_key
            .iter()
            .map(|g| g.into_affine())
            .collect::<Vec<_>>();
        let expected_commitment =
            G::msm(commit_key_affine.as_slice(), hashed_logs_vec.as_slice()).unwrap();
        assert_eq!(commitment.into_affine(), expected_commitment);

        // Check that unrolled commitment values are as expected
        let expected_commitment_5 = commit_key[5].mul(hashed_logs_vec[5]);
        assert_eq!(unrolled_commitment[5], expected_commitment_5);
    }

    // Test commit_and_merkle
    // Use randomly generated vector of G1Projective and Fr
    #[test]
    fn test_commit_and_merkle() {
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
        let (_commitment, merkle_tree, _) =
            commit_and_merkle(commit_key.clone(), hashed_logs_vec.clone());

        // Check inclusion proof
        let mut test_bytes = Vec::new();
        commit_key[5]
            .mul(hashed_logs_vec[5])
            .serialize_compressed(&mut test_bytes)
            .unwrap();
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
        let key = 1usize;
        let mut key_buf = BytesMut::new();
        key.encode(&mut key_buf);
        let proof = trie.get_proof(&key_buf).unwrap();
        let root = trie.root().unwrap();
        assert!(trie.verify_proof(root.as_slice(), &key_buf, proof).is_ok());

        let test_receipt = receipts[key].clone();
        let bloom_receipt = ReceiptWithBloomRef::from(&test_receipt);
        let mut value_buf = BytesMut::new();
        bloom_receipt.encode_inner(&mut value_buf, false);

        assert_eq!(trie.get(&key_buf).unwrap(), Some(value_buf.to_vec()));
    }

    // Test OvcProver and OvcVerifier
    #[test]
    fn test_ovc() {
        let log_num_receipts = 6;
        let num_receipts = 2usize.pow(log_num_receipts);
        let diff_idx = 2usize.pow(log_num_receipts)-2;
        // Generate random vector of G1Projective
        let mut rng = ark_std::test_rng();
        let mut commit_key: Vec<G1Projective> = Vec::new();
        for _ in 0..num_receipts {
            commit_key.push(G1Projective::rand(&mut rng));
        }

        // Read receipts and commit
        let receipts_json = std::fs::read("receipts_full.json").unwrap();
        let receipts: Vec<Receipt> = serde_json::from_slice(receipts_json.as_slice()).unwrap();
        let mut receipt_trie = build_from_receipts(receipts.clone());

        let mut hashed_logs_vec = Vec::new();
        for idx in 0..num_receipts {
            hashed_logs_vec.push(hash_receipts_vec(&receipts[idx]));
        }

        // Compute Merkle tree
        let (commitment, merkle_tree, unrolled_commits) =
            commit_and_merkle(commit_key.clone(), hashed_logs_vec.clone());

        // Generate proof
        let key = diff_idx;
        let inclusion_proof = merkle_tree.generate_proof(key).unwrap();
        let root = merkle_tree.root();
        let mut test_bytes = Vec::new();
        commit_key[key]
            .mul(hashed_logs_vec[key])
            .serialize_compressed(&mut test_bytes)
            .unwrap();

        // Verify proof
        assert!(inclusion_proof.verify(&(), &(), &root, test_bytes).unwrap());

        // Generate proof for OVC
        let mut ovc_prover_1 =
            OvcProver::new(commit_key.clone(), receipts[0..num_receipts].to_vec());

        // Skip a receipt
        let mut receipts_2 = receipts[0..diff_idx].to_vec();
        receipts_2.extend_from_slice(&receipts[diff_idx+1..num_receipts+1]);
        // receipts_2[diff_idx] = receipts_2[6].clone();
        let mut ovc_prover_2 = OvcProver::new(commit_key.clone(), receipts_2.clone());

        let mut ovc_verifier = OvcVerifier {
            prover_1_root: ovc_prover_1.clone().root,
            prover_2_root: ovc_prover_2.clone().root,
            tree_size: num_receipts,
            commitment_key: commit_key,
        };

        let prover_1_response = ovc_prover_1.first_response();
        let prover_2_response = ovc_prover_2.first_response();
        let mut verifier_request = ovc_verifier.find_disagreement_step(prover_1_response.left, prover_1_response.right, prover_2_response.left, prover_2_response.right);

        for _ in 0..log_num_receipts {
            let prover_1_response = ovc_prover_1.reply_to_verifier_step(&verifier_request);
            let prover_2_response = ovc_prover_2.reply_to_verifier_step(&verifier_request);
            match (prover_1_response, prover_2_response) {
                (Response::StepResponse{left: l1, right: r1}, Response::StepResponse{left: l2, right: r2}) => {
                    verifier_request = ovc_verifier.find_disagreement_step(l1,r1,l2, r2);
                }

                (Response::Leaf(l1), Response::Leaf(l2)) => {
                    let proof_1 = ovc_prover_1.clone().compute_opening_proof(&receipt_trie, receipts[diff_idx].clone());
                    let proof_2 = ovc_prover_2.clone().compute_opening_proof(&receipt_trie, receipts_2[diff_idx].clone());
                    assert_eq!(ovc_verifier.final_check(diff_idx, proof_1, receipt_trie.root().unwrap(), proof_2, receipt_trie.root().unwrap()), Winner::Both);
                    assert_eq!(l1, unrolled_commits[diff_idx]);
                    assert_ne!(l2, unrolled_commits[diff_idx]);
                    assert_eq!(ovc_prover_1.disagreement_idx, diff_idx);
                    assert_eq!(ovc_prover_2.disagreement_idx, diff_idx);

                    
                }
                _ => panic!("Mismatched provers"),
            }
            
            
        }

        
    }
}
