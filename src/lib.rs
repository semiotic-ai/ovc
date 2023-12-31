use ark_bn254::{Fr, G1Projective};
use ark_crypto_primitives::merkle_tree::DigestConverter;
use ark_crypto_primitives::{
    crh::{sha256::Sha256, CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{ByteDigestConverter, Config, MerkleTree},
};
use ark_ff::fields::field_hashers::{DefaultFieldHasher, HashToField};
use ark_serialize::CanonicalSerialize;
use std::ops::Mul;

pub mod filtered_event_proof;
pub mod receipts_proof;
mod tests;

/// Prover: This is the Prover in the optimistically verifiable commitment protocol.
/// It takes a commitment key and a list of receipts and generates a commitment and a Merkle tree using the incremental steps of the commitment calculation as leaves.
#[derive(Clone, Debug)]
pub struct Prover<P, T, W> {
    root: Vec<u8>,
    left_leaves: Vec<Vec<u8>>,
    right_leaves: Vec<Vec<u8>>,
    commitment: G1Projective,
    disagreement_idx: usize,
    _phantom: std::marker::PhantomData<P>,
    _phantom2: std::marker::PhantomData<T>,
    _phantom3: std::marker::PhantomData<W>,
}

/// A struct containing responses from the `Prover` for one round of interaction in the OVC protocol.
///
/// # Fields
/// - `left`: The left child of a Merkle tree node.
/// - `right`: The right child of a Merkle tree node.
pub struct StepResponse {
    pub left: Vec<u8>,
    pub right: Vec<u8>,
}

/// A wrapper for the two types of responses that can be sent by a Prover.
pub enum Response {
    StepResponse(StepResponse),
    Leaf(Vec<u8>),
}

impl<P: OpeningProof<T, W>, T, W> Prover<P, T, W> {
    /// Constructs a new `Prover`.
    ///
    /// Initializes a Prover instance, committing to the Receipts and building the Merkle tree
    /// required for verifying the commitment.
    ///
    /// # Parameters
    /// - `commit_key`: The commitment key used for committing to the Receipts.
    /// - `receipts`: A vector of Receipts to which the Prover will commit.
    ///
    /// # Returns
    /// A new `Prover` instance.
    pub fn new(commit_key: Vec<G1Projective>, data_bytes_vec: Vec<Vec<u8>>) -> Prover<P, T, W> {
        let hash_vec: Vec<Fr> = data_bytes_vec
            .iter()
            .map(|bytes| hash_vec(bytes.clone()))
            .collect();

        let (commitment, tree, leaves) = commit_and_merkle(commit_key.clone(), hash_vec);
        Prover {
            root: tree.root(),
            left_leaves: leaves[0..leaves.len() / 2].to_vec(),
            right_leaves: leaves[leaves.len() / 2..leaves.len()].to_vec(),
            commitment,
            disagreement_idx: 0,
            _phantom: std::marker::PhantomData,
            _phantom2: std::marker::PhantomData,
            _phantom3: std::marker::PhantomData,
        }
    }

    /// Retrieves the commitment to receipts and the Merkle tree root for commitment verification.
    ///
    /// # Returns
    /// A tuple containing the commitment and Merkle tree root.
    pub fn get_commitment_and_root(&self) -> (G1Projective, Vec<u8>) {
        (self.commitment, self.root.clone())
    }

    pub fn get_disagreement_idx(&self) -> usize {
        self.disagreement_idx
    }

    /// Generates the initial response in the OVC protocol by the `Prover`.
    ///
    /// # Returns
    ///
    /// A `StepResponse` containing the left and right roots of the Merkle subtrees.
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

    /// Generates a response for a single round in the OVC dispute protocol.
    ///
    /// # Arguments
    ///
    /// * `open_side` - An `OpenKind` enum specifying which side (left/right) should be opened.
    ///
    /// # Returns
    ///
    /// A `Response` that can be a `StepResponse` or a `Leaf` depending on the protocol step.
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
    pub fn compute_opening_proof(&self, witness: &W, input_data: T) -> P {
        P::new(input_data, witness)
    }
}

/// The Referee in the OVC protocol.
/// Interacts with two Provers, keeping track of the latest node for each prover, the tree size at a given round, and the commitment key used to commit to Receipts.
#[derive(Clone)]
pub struct Referee<P, T, S> {
    prover_1_root: Vec<u8>,
    prover_2_root: Vec<u8>,
    tree_size: usize,
    commitment_key: Vec<G1Projective>,
    _phantom: std::marker::PhantomData<P>,
    _phantom2: std::marker::PhantomData<T>,
    _phantom3: std::marker::PhantomData<S>,
}

/// Enum representing the possible opening kinds in a protocol step.
///
/// * `Left` indicates that the left child should be opened.
/// * `Right` indicates that the right child should be opened.
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

pub trait OpeningProof<T, W> {
    fn new(input_data: T, witness: &W) -> Self;

    fn verify(
        self,
        commitment_key: G1Projective,
        commitment_bytes: &Vec<u8>,
        disagreement_idx: usize,
        root_hash: &[u8],
    ) -> bool;
}

impl<P: OpeningProof<T, S>, T, S> Referee<P, T, S> {
    /// Creates a new Referee.
    ///
    pub fn new(
        prover_1_root: Vec<u8>,
        prover_2_root: Vec<u8>,
        tree_size: usize,
        commitment_key: Vec<G1Projective>,
    ) -> Self {
        Referee {
            prover_1_root,
            prover_2_root,
            tree_size,
            commitment_key,
            _phantom: std::marker::PhantomData,
            _phantom2: std::marker::PhantomData,
            _phantom3: std::marker::PhantomData,
        }
    }
    /// Determines which child node to use for the next protocol round based on the disagreement
    /// between prover responses.
    ///
    /// # Arguments
    ///
    /// * `prover_1_response` - A `StepResponse` from the first prover.
    /// * `prover_2_response` - A `StepResponse` from the second prover.
    ///
    /// # Returns
    ///
    /// An `OpenKind` enum indicating whether to open the left or right child in the next round.
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
        proof_1: P,
        root_1_hash: <CompressH as TwoToOneCRHScheme>::Output,
        serialized_commitment_1: Vec<u8>,
        proof_2: P,
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
fn hash_vec(bytes_vec: Vec<u8>) -> Fr {
    let hasher = <DefaultFieldHasher<Sha256> as HashToField<Fr>>::new(&[1]);
    hasher.hash_to_field(bytes_vec.as_slice(), 1)[0]
}
