use std::ops::Mul;

use ark_serialize::CanonicalSerialize;
use cita_trie::verify_proof;
use hasher::HasherKeccak;
use reth_codecs::Compact;
use reth_primitives::{Receipt, ReceiptWithBloomRef};
use reth_rlp::Encodable;
use revm_primitives::bytes::BytesMut;

use crate::{hash_vec, receipts_proof::ReceiptProver, OpeningProof};

pub mod uniswap_v2;

pub trait Event {
    fn is_event_in_receipt(&self, receipt: &Receipt) -> bool;
}

pub struct EventReceipt<E: Event> {
    event: E,
    receipt: Receipt,
}

// Define a new struct `EventOpeningProof` to represent the proof of opening an event.
pub struct EventOpeningProof<E: Event> {
    pub event: E,
    pub receipt: Receipt,
    pub inclusion_proof: Vec<Vec<u8>>,
}

// Implement the `OpeningProof` trait for `EventOpeningProof`.
impl<E: Event> OpeningProof<EventReceipt<E>, Vec<Receipt>> for EventOpeningProof<E> {
    fn new(input_data: EventReceipt<E>, witness: &Vec<Receipt>) -> Self {
        let inclusion_proof = input_data.receipt.get_proof(witness);
        EventOpeningProof {
            event: input_data.event,
            receipt: input_data.receipt,
            inclusion_proof,
        }
    }

    fn verify(
        self,
        commitment_key: ark_bn254::G1Projective,
        commitment_bytes: &Vec<u8>,
        disagreement_idx: usize,
        root_hash: &[u8],
    ) -> bool {
        // Check that the event is included in the claimed receipt
        if !self.event.is_event_in_receipt(&self.receipt) {
            return false;
        }

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
