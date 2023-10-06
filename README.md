# Optimistically Verifiable Commitment Protocol

## Description

This Rust library implements an Optimistically Verifiable Commitment Protocol, providing structures and methods to create commitments using a Merkle tree and subsequently verify them. It primarily consists of a `Prover` that generates a commitment and a `Referee` that interacts with two provers to find disagreements and verify proofs in a dispute protocol.

### Key Components

- **Prover**: Generates a commitment to a list of Ethereum receipts, using a commitment key, and builds the Merkle tree to verify that the commitment was created correctly.
- **Referee**: Interacts with two provers, keeping track of their latest nodes, tree size at a given round, and the commitment key used to commit to Receipts.

### Functionality

- Creation of commitment to receipts and Merkle tree.
- Initial response and a single round in the OVC dispute protocol by the prover.
- Computing opening proof at the end OVC protocol by the prover.
- Verification of opening proof by both the referee.

## Prerequisites

- Rust
- ...

## Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/semiotic-ai/ovc.git
   ```
2. Navigate to the project directory:
   ```sh
   cd ovc
   ```
3. Build the project:
   ```sh
   cargo build --release
   ```

## Usage

### Prover

- Initialize a Prover instance using a commitment key and a list of receipts to be commited to.
- Generate a commitment and Merkle tree and obtain the initial response in the OVC protocol.
- Participate in a round in the OVC dispute protocol, either revealing the leaf node at the disagreement point or producing a validity proof for that leaf node.

### Referee

- Interact with two provers to find disagreement points in the Merkle tree.
- Perform verification of the proofs provided by the provers to determine a winner in case of disagreement.

### Example

```rust
	use ovc::*;
    	use ark_bn254::G1Projective as G;
    	use ark_ec::{CurveGroup, VariableBaseMSM};
    	use ark_std::UniformRand;
    	use serde_json;
    	use std::sync::Arc;

	fn load_receipts() -> Vec<Receipt> {
        let receipts_json = std::fs::read("src/tests/data/receipts_full.json").unwrap();
        let receipts: Vec<Receipt> = serde_json::from_slice(receipts_json.as_slice()).unwrap();
        receipts
    }

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
        let mut ovc_prover_1 = Prover::new(commit_key.clone(), receipts[0..num_receipts].to_vec());

        // Skip a receipt to simulate a prover who misses a receipt
        let mut receipts_2 = receipts[0..diff_idx].to_vec();
        receipts_2.extend_from_slice(&receipts[diff_idx + 1..num_receipts + 1]);
        let mut ovc_prover_2 = Prover::new(commit_key.clone(), receipts_2.clone());

        // First check if the commitments provided by the two provers differ
        let (prover_1_commitment, prover_1_root) = ovc_prover_1.get_commitment_and_root();
        let (prover_2_commitment, prover_2_root) = ovc_prover_2.get_commitment_and_root();
        assert_ne!(prover_1_commitment, prover_2_commitment);

        // Initialize referee
        let mut ovc_verifier = Referee {
            prover_1_root,
            prover_2_root,
            tree_size: num_receipts,
            commitment_key: commit_key,
        };

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
                    assert_eq!(ovc_prover_1.clone().disagreement_idx, diff_idx);
                    assert_eq!(ovc_prover_2.clone().disagreement_idx, diff_idx);

                    let mut diff_idx_bytes = BytesMut::new();
                    diff_idx.encode(&mut diff_idx_bytes);

                    let proof_1 = ovc_prover_1
                        .clone()
                        .compute_opening_proof(&receipt_trie, receipts[diff_idx].clone());
                    let proof_2 = ovc_prover_2
                        .clone()
                        .compute_opening_proof(&receipt_trie, receipts_2[diff_idx].clone());
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
```

## Testing

To run tests, use:

```sh
cargo test
```

## Contribution

If you would like to contribute to this project, please ...

## License

## Contact

## Acknowledgements

- [Dependencies/References]
