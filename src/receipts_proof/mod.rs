use std::{ops::Mul, sync::Arc};

use ark_bn254::G1Projective;
use ark_serialize::CanonicalSerialize;
use cita_trie::{verify_proof, PatriciaTrie, MemoryDB, Trie};
use hasher::HasherKeccak;
use reth_codecs::Compact;
use reth_primitives::{Receipt, ReceiptWithBloomRef};
use reth_rlp::Encodable;
use revm_primitives::bytes::BytesMut;

use crate::{OpeningProof, hash_vec};


/// Holds the opening proof revealed by Provers at the end of the protocol.
#[derive(Clone)]
pub struct ReceiptOpeningProof {
    pub receipt: Receipt,
    pub inclusion_proof: Vec<Vec<u8>>,
}

pub trait ReceiptProver {
    fn get_idx_in_block(&self, leaves: Vec<Receipt>) -> usize;
    fn get_proof(&self, leaves: &Vec<Receipt>) -> Vec<Vec<u8>>;
}

impl ReceiptProver for Receipt {
    fn get_idx_in_block(&self, leaves: Vec<Receipt>) -> usize {
        leaves.iter().position(|x| x == self).unwrap()
    }

    fn get_proof(&self, leaves: &Vec<Receipt>) -> Vec<Vec<u8>> {
        let mut receipts_trie = build_from_receipts(leaves.clone());
        let receipt_idx = self.get_idx_in_block(leaves.to_vec());
        let mut receipt_idx_buf = BytesMut::new();
        receipt_idx.encode(&mut receipt_idx_buf);
        let _build_tree = receipts_trie.root();
        receipts_trie.get_proof(&receipt_idx_buf).unwrap()
    }
}

impl OpeningProof<Receipt, Vec<Receipt>> for ReceiptOpeningProof{
    /// Creates a new opening proof.
    /// 
    
    fn new(receipt: Receipt, witness: &Vec<Receipt>) -> Self {
        let inclusion_proof = receipt.get_proof(&witness);
        ReceiptOpeningProof {
            receipt,
            inclusion_proof,
        }
    }
    /// Verifies an opening proof.
    ///
    /// # Arguments
    ///
    /// * `commitment_key` - The G1Projective commitment key.
    /// * `commitment_bytes` - The byte representation of the commitment.
    /// * `disagreement_idx` - The index at which the disagreement occurred.
    /// * `root_hash` - The root hash of the Merkle tree.
    ///
    /// # Returns
    ///
    /// A boolean value indicating whether the verification was successful.
    fn verify(
        self,
        commitment_key: G1Projective,
        commitment_bytes: &Vec<u8>,
        disagreement_idx: usize,
        root_hash: &[u8],
    ) -> bool {
        // Check that receipt opening the commitment is correct
        let mut receipts_bytes = Vec::new();
        self.receipt.clone().to_compact(&mut receipts_bytes);
        let hashed_receipt = hash_vec(receipts_bytes);
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

/// Builds a Patricia trie from a vector of receipts.
fn build_from_receipts(receipts: Vec<Receipt>) -> PatriciaTrie<MemoryDB, HasherKeccak> {
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