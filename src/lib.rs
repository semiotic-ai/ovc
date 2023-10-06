use ark_bn254::{Fr, G1Projective};
use ark_crypto_primitives::merkle_tree::DigestConverter;
use ark_crypto_primitives::{
    crh::{sha256::Sha256, CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{ByteDigestConverter, Config, MerkleTree},
};
use ark_ff::fields::field_hashers::{DefaultFieldHasher, HashToField};
use ark_serialize::CanonicalSerialize;
use cita_trie::{verify_proof, MemoryDB, PatriciaTrie, Trie};
use hasher::HasherKeccak;
use reth_codecs::Compact;
use reth_primitives::{bytes::BytesMut, Receipt, ReceiptWithBloomRef};
use reth_rlp::Encodable;
use std::ops::Mul;

mod tests;

/// Prover: This is the Prover in the optimistically verifiable commitment protocol. 
/// It takes a commitment key and a list of receipts and generates a commitment and a Merkle tree using the incremental steps of the commitment calculation as leaves.
#[derive(Clone, Debug)]
pub struct Prover {
    root: Vec<u8>,
    left_leaves: Vec<Vec<u8>>,
    right_leaves: Vec<Vec<u8>>,
    commitment: G1Projective,
    disagreement_idx: usize,
}

/// Response from the prover for one round of interaction in the OVC protocol.
/// It contains the children of the node requested by the Referee
pub struct StepResponse {
    pub left: Vec<u8>,
    pub right: Vec<u8>,
}

/// A wrapper for the two types of responses that can be sent by a Prover.
pub enum Response {
    StepResponse(StepResponse),
    Leaf(Vec<u8>),
}

impl Prover {
    /// Initializes a Prover instance.
    /// Requires a commitment key used for committing to the Receipts.
    /// Commits to the Receipts and builds the Merkle tree for verifying the commitment.
    pub fn new(commit_key: Vec<G1Projective>, receipts: Vec<Receipt>) -> Prover {
        let hash_receipts_vec: Vec<Fr> = receipts
            .iter()
            .map(|receipt| hash_receipts_vec(receipt))
            .collect();

        let (commitment, tree, leaves) = commit_and_merkle(commit_key.clone(), hash_receipts_vec);
        Prover {
            root: tree.root(),
            left_leaves: leaves[0..leaves.len() / 2].to_vec(),
            right_leaves: leaves[leaves.len() / 2..leaves.len()].to_vec(),
            commitment,
            disagreement_idx: 0,
        }
    }

    /// A getter function to return the commitment to receipts and the Merkle tree root for commitment verification
    pub fn get_commitment_and_root(&self) -> (G1Projective, Vec<u8>) {
        (self.commitment, self.root.clone())
    }

    /// The Provers initial response in the OVC protocol
    pub fn first_response(&mut self) -> StepResponse {
        let left_leaves = self.left_leaves.clone();
        let right_leaves = self.right_leaves.clone();
        let left_tree = Sha256MerkleTree::new(&(), &(), left_leaves.clone()).unwrap();
        let right_tree = Sha256MerkleTree::new(&(), &(), right_leaves.clone()).unwrap();

        StepResponse {
            left: left_tree.root(),
            right: right_tree.root(),
        }
    }

    /// A single round in the OVC dispute protocol
    pub fn find_disagreement_step_response(&mut self, open_side: &OpenKind) -> Response {
        let leaves = match open_side {
            OpenKind::Left => self.left_leaves.clone(),
            OpenKind::Right => self.right_leaves.clone(),
        };

        self.disagreement_idx = 2 * self.disagreement_idx
            + match open_side {
                OpenKind::Left => 0,
                OpenKind::Right => 1,
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
            return Response::StepResponse(StepResponse {
                left: left_leaf_hash,
                right: right_leaf_hash,
            });
        } else {
            let left_tree = Sha256MerkleTree::new(&(), &(), left_leaves.clone()).unwrap();
            let right_tree = Sha256MerkleTree::new(&(), &(), right_leaves.clone()).unwrap();
            self.left_leaves = left_leaves;
            self.right_leaves = right_leaves;
            Response::StepResponse(StepResponse {
                left: left_tree.root(),
                right: right_tree.root(),
            })
        }
    }

    /// The final step in the OVC protocol.
    /// Reveals the leaf node at the disagreement point and produces a validity proof for that leaf node.
    pub fn compute_opening_proof(
        self,
        receipt_trie: &PatriciaTrie<MemoryDB, HasherKeccak>,
        receipt: Receipt,
    ) -> OpeningProof {
        let mut disagreement_idx_buf = BytesMut::new();
        self.disagreement_idx.encode(&mut disagreement_idx_buf);
        let inclusion_proof = receipt_trie.get_proof(&disagreement_idx_buf).unwrap();
        OpeningProof {
            receipt,
            inclusion_proof,
        }
    }
}

/// The Referee in the OVC protocol. 
/// Interacts with two Provers, keeping track of the latest node for each prover, the tree size at a given round, and the commitment key used to commit to Receipts.
#[derive(Clone)]
pub struct Referee {
    prover_1_root: Vec<u8>,
    prover_2_root: Vec<u8>,
    tree_size: usize,
    commitment_key: Vec<G1Projective>,
}

/// The message from the Referee indicating which child to use for the next round of the protocol.
#[derive(Debug, PartialEq)]
pub enum OpenKind {
    Left,
    Right,
}

/// A message from the Referee indicating who one the game.
#[derive(Debug, PartialEq)]
pub enum Winner {
    Both,
    Prover1,
    Prover2,
    Neither,
}

/// Holds the opening proof revealed by Provers at the end of the protocol.
pub struct OpeningProof {
    pub receipt: Receipt,
    pub inclusion_proof: Vec<Vec<u8>>,
}

impl OpeningProof {
    /// Performs the verification of an opening proof. 
    /// Right now this is specific to performing Merkle inclusion proofs of Receipts in a block header.
    /// Will need to be updated to support e.g. data indexed using Substreams
    pub fn verify(
        self,
        commitment_key: G1Projective,
        commitment_bytes: &Vec<u8>,
        disagreement_idx: usize,
        root_hash: &[u8],
    ) -> bool {
        // Check that receipt opening the commitment is correct
        let hashed_receipt = hash_receipts_vec(&self.receipt);
        let commitment = commitment_key.mul(hashed_receipt);
        let mut serialized_commitment_bytes = Vec::new();
        commitment
            .serialize_compressed(&mut serialized_commitment_bytes)
            .unwrap();

        if *commitment_bytes != serialized_commitment_bytes {
            return false;
        }

        // Check that inclusion proof is valid with computed commitment
        let mut disagreement_idx_buf = BytesMut::new();
        disagreement_idx.encode(&mut disagreement_idx_buf);
        let hasher = HasherKeccak::new();
        let proof = verify_proof(
            &root_hash,
            &disagreement_idx_buf,
            self.inclusion_proof,
            hasher,
        );

        // Check that proof is valid receipt at leaf in opening proof matches claimed receipt
        let valid_proof = match proof {
            Ok(res) => res,
            Err(_) => return false,
        };

        let bloom_receipt = ReceiptWithBloomRef::from(&self.receipt);
        let mut value_buf = BytesMut::new();
        bloom_receipt.encode_inner(&mut value_buf, false);
        match valid_proof {
            Some(leaf_bytes) => return value_buf == leaf_bytes,
            None => return false,
        }
    }
}

impl Referee {
    /// Performs one round of the Referee's role.
    /// Checks which child nodes the provers disagree on and asks to open the earliest disagreement.
    pub fn find_disagreement_step(
        &mut self,
        prover_1_response: StepResponse,
        prover_2_response: StepResponse,
    ) -> OpenKind {
        let prover_1_l_child = prover_1_response.left;
        let prover_1_r_child = prover_1_response.right;
        let prover_2_l_child = prover_2_response.left;
        let prover_2_r_child = prover_2_response.right;

        let prover_1_node;
        let prover_2_node;
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
            return OpenKind::Left;
        } else {
            self.prover_1_root = prover_1_r_child;
            self.prover_2_root = prover_2_r_child;
            self.tree_size = self.tree_size / 2;
            return OpenKind::Right;
        }
    }

    /// Verifies the proofs provided by the provers and determines a winner.
    pub fn opening_proof_verify(
        &self,
        disagreement_idx: usize,
        proof_1: OpeningProof,
        root_1_hash: <CompressH as TwoToOneCRHScheme>::Output,
        serialized_commitment_1: Vec<u8>,
        proof_2: OpeningProof,
        root_2_hash: <CompressH as TwoToOneCRHScheme>::Output,
        serialized_commitment_2: Vec<u8>,
    ) -> Winner {
        let prover_1_passed = proof_1.verify(
            self.commitment_key[disagreement_idx],
            &serialized_commitment_1,
            disagreement_idx,
            &root_1_hash,
        );
        let prover_2_passed = proof_2.verify(
            self.commitment_key[disagreement_idx],
            &serialized_commitment_2,
            disagreement_idx,
            &root_2_hash,
        );

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

fn commit_unrolled(
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

fn commit_and_merkle(
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
fn hash_receipts_vec(receipt: &Receipt) -> Fr {
    let mut receipt_bytes = Vec::new();
    receipt.clone().to_compact(&mut receipt_bytes);
    let hasher = <DefaultFieldHasher<Sha256> as HashToField<Fr>>::new(&[1]);
    hasher.hash_to_field(receipt_bytes.as_slice(), 1)[0]
}
