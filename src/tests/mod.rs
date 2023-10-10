// Test module for OVC
#[cfg(test)]
mod ovc_tests {
    use crate::{*, receipts_proof::ReceiptOpeningProof, filtered_event_proof::{uniswap_v2::{UniswapV2Event, UniswapV2Swap}, Event}};
    use ark_bn254::G1Projective as G;
    use ark_ec::{CurveGroup, VariableBaseMSM};
    use ark_std::UniformRand;
    use cita_trie::{PatriciaTrie, MemoryDB, Trie};
    use csv;
    use hasher::HasherKeccak;
    use reth_codecs::Compact;
    use reth_primitives::{Receipt, ReceiptWithBloomRef};
    use reth_rlp::Encodable;
    use revm_primitives::bytes::BytesMut;
    use serde_json;
    use std::{sync::Arc, error::Error, io};

    fn load_receipts() -> Vec<Receipt> {
        let receipts_json = std::fs::read("src/tests/data/receipts_full.json").unwrap();
        let receipts: Vec<Receipt> = serde_json::from_slice(receipts_json.as_slice()).unwrap();
        receipts
    }

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


    fn read_events() -> Result<Vec<UniswapV2Event>, Box<dyn Error>> {
        let mut rdr = csv::Reader::from_reader(io::stdin());
        let mut event_vec = Vec::new();
        for result in rdr.deserialize() {
            // Notice that we need to provide a type hint for automatic
            // deserialization.
            let event: UniswapV2Event = result?;
            event_vec.push(event);
        }

        Ok(event_vec)
    }

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
        let receipts = load_receipts();
        let mut hashed_logs_vec = Vec::new();
        for idx in 0..8 {
            let mut receipt_bytes = Vec::new();
            receipts[idx].clone().to_compact(&mut receipt_bytes);
            hashed_logs_vec.push(hash_vec(receipt_bytes));
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
        let receipts = load_receipts();
        let mut trie = build_from_receipts(receipts);

        let root = trie.root().unwrap();
        let expected_root: Vec<u8> = vec![
            185, 88, 3, 170, 120, 72, 90, 37, 229, 227, 35, 15, 209, 61, 208, 231, 131, 76, 245,
            59, 29, 47, 17, 36, 140, 66, 89, 202, 172, 239, 111, 201,
        ];

        assert_eq!(root, expected_root);
    }

    #[test]
    fn test_inclusion_proof() {
        let receipts = load_receipts();

        let mut trie = build_from_receipts(receipts.clone());
        let root = trie.root().unwrap();

        let key = 62usize;
        let mut key_buf = BytesMut::new();
        key.encode(&mut key_buf);

        let proof = trie.get_proof(&key_buf).unwrap();
        let leaf_val_proof = trie.verify_proof(&root, &key_buf, proof).unwrap();

        let test_receipt = receipts[key].clone();
        let bloom_receipt = ReceiptWithBloomRef::from(&test_receipt);
        let mut value_buf = BytesMut::new();
        bloom_receipt.encode_inner(&mut value_buf, false);

        assert_eq!(leaf_val_proof, Some(value_buf.to_vec()));
    }

    // Test Prover and Referee
    #[test]
    fn test_ovc() {
        let log_num_receipts = 6;
        let num_receipts = 2usize.pow(log_num_receipts);
        let diff_idx = 2usize.pow(log_num_receipts) - 7;

        // Generate random vector of G1Projective
        let mut rng = ark_std::test_rng();
        let mut commit_key: Vec<G1Projective> = Vec::new();
        for _ in 0..num_receipts {
            commit_key.push(G1Projective::rand(&mut rng));
        }

        // Read receipts and build receipt trie
        let receipts = load_receipts();
        let mut receipt_trie = build_from_receipts(receipts.clone());
        let receipt_root = receipt_trie.root().unwrap();

        // Run OVC protocol
        let mut receipts_bytes_vec = Vec::new();
        for idx in 0..num_receipts {
            let mut receipt_bytes = Vec::new();
            receipts[idx].clone().to_compact(&mut receipt_bytes);
            receipts_bytes_vec.push(receipt_bytes);
        }
        let mut ovc_prover_1 = Prover::<ReceiptOpeningProof, Receipt, Vec<Receipt>>::new(commit_key.clone(), receipts_bytes_vec);

        // Skip a receipt to simulate a prover who misses a receipt
        let mut receipts_2 = receipts[0..diff_idx].to_vec();
        receipts_2.extend_from_slice(&receipts[diff_idx + 1..num_receipts + 1]);
        let mut receipts_bytes_vec_2 = Vec::new();
        for idx in 0..num_receipts {
            let mut receipt_bytes = Vec::new();
            receipts_2[idx].clone().to_compact(&mut receipt_bytes);
            receipts_bytes_vec_2.push(receipt_bytes);
        }
        let mut ovc_prover_2 = Prover::<ReceiptOpeningProof, Receipt, Vec<Receipt>>::new(commit_key.clone(), receipts_bytes_vec_2);

        // First check if the commitments provided by the two provers differ
        let (prover_1_commitment, prover_1_root) = ovc_prover_1.get_commitment_and_root();
        let (prover_2_commitment, prover_2_root) = ovc_prover_2.get_commitment_and_root();
        assert_ne!(prover_1_commitment, prover_2_commitment);

        // Initialize referee
        let mut ovc_verifier:Referee<ReceiptOpeningProof, Receipt, Vec<Receipt>>  = Referee::new(prover_1_root, prover_2_root, num_receipts, commit_key);

        // Run OVC protocol
        let prover_1_response = ovc_prover_1.first_response();
        let prover_2_response = ovc_prover_2.first_response();
        let mut verifier_request =
            ovc_verifier.find_disagreement_step(prover_1_response, prover_2_response);

        for _ in 0..log_num_receipts {
            let prover_1_response = ovc_prover_1.find_disagreement_step_response(&verifier_request);
            let prover_2_response = ovc_prover_2.find_disagreement_step_response(&verifier_request);
            match (prover_1_response, prover_2_response) {
                (Response::StepResponse(resp1), Response::StepResponse(resp2)) => {
                    verifier_request = ovc_verifier.find_disagreement_step(resp1, resp2);
                }

                (Response::Leaf(l1), Response::Leaf(l2)) => {
                    assert_eq!(ovc_prover_1.get_disagreement_idx(), diff_idx);
                    assert_eq!(ovc_prover_2.get_disagreement_idx(), diff_idx);

                    let mut diff_idx_bytes = BytesMut::new();
                    diff_idx.encode(&mut diff_idx_bytes);

                    let proof_1 = ovc_prover_1
                        .compute_opening_proof(&receipts, receipts[diff_idx].clone());
                    let proof_2 = ovc_prover_2
                        .compute_opening_proof(&receipts, receipts_2[diff_idx].clone());
                    assert_eq!(
                        ovc_verifier.opening_proof_verify(
                            diff_idx,
                            proof_1,
                            receipt_root.clone(),
                            l1.clone(),
                            proof_2,
                            receipt_root.clone(),
                            l2.clone()
                        ),
                        Winner::Prover1
                    );
                }
                _ => panic!("Mismatched provers"),
            }
        }
    }

    #[test]
    fn test_is_event_in_receipt() {
        let receipts = load_receipts();
        let swap = UniswapV2Event::new(
                "1487592416523998074".to_owned(),
                "0".to_owned(),
                "0".to_owned(),
                "71530900099000000000000000000".to_owned(),
                "0".to_owned(),
                "0".to_owned(),
                "0".to_owned(),
                "0".to_owned(),
                "0".to_owned(),
                "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D".to_owned(),
                "0x40fbA1C5aFB5c03E80C2CA2C07c38B5bD9d4d150".to_owned(),
            );

        let num_events_in_block = receipts.iter().map(|r| swap.is_event_in_receipt(r)).filter(|x| *x).count();
        assert_eq!(num_events_in_block, 1);
        
    }
}
