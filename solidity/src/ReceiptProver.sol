// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/utils/cryptography/MerkleProof.sol";

contract ReceiptProver {
    struct Receipt {
        bytes32 receiptHash; // Placeholder for the actual receipt data (hashed)
    }

    struct ReceiptOpeningProof {
        Receipt receipt;
        bytes32[] inclusionProof; // Merkle proof
    }

    // Function to get the index of a receipt in a list of receipts (simplified)
    function getIdxInBlock(Receipt memory receipt, Receipt[] memory leaves) public pure returns (uint256) {
        for (uint256 i = 0; i < leaves.length; i++) {
            if (leaves[i].receiptHash == receipt.receiptHash) {
                return i;
            }
        }
        revert("Receipt not found in block");
    }

    // Function to build a Merkle proof for a given receipt
    function getProof(Receipt memory receipt, bytes32[] memory leafHashes, bytes32 merkleRoot)
        public
        pure
        returns (bytes32[] memory)
    {
        // Merkle proof can be generated off-chain, but the verification is done on-chain using MerkleProof library
        // This function serves as a placeholder.
        return leafHashes; // Placeholder for actual proof generation logic.
    }

    // Function to verify an opening proof using Merkle proof verification
    function verify(ReceiptOpeningProof memory openingProof, bytes32 merkleRoot) public pure returns (bool) {
        bytes32 leafHash = keccak256(abi.encodePacked(openingProof.receipt.receiptHash));
        bool proofValid = MerkleProof.verify(openingProof.inclusionProof, merkleRoot, leafHash);
        return proofValid;
    }

    // Simplified example for creating a new ReceiptOpeningProof
    function createReceiptOpeningProof(Receipt memory receipt, bytes32[] memory leafHashes, bytes32 merkleRoot)
        public
        pure
        returns (ReceiptOpeningProof memory)
    {
        bytes32[] memory proof = getProof(receipt, leafHashes, merkleRoot);
        return ReceiptOpeningProof(receipt, proof);
    }

    // Helper function to build a Merkle tree from an array of receipts (returns only the leaf hashes)
    function buildFromReceipts(Receipt[] memory receipts) public pure returns (bytes32[] memory) {
        bytes32[] memory leafHashes = new bytes32[](receipts.length);
        for (uint256 i = 0; i < receipts.length; i++) {
            leafHashes[i] = keccak256(abi.encodePacked(receipts[i].receiptHash));
        }
        return leafHashes;
    }

    // Example function to verify receipt inclusion in Merkle root (assuming off-chain proof generation)
    function verifyReceiptInclusion(Receipt memory receipt, bytes32 merkleRoot, bytes32[] memory proof)
        public
        pure
        returns (bool)
    {
        bytes32 leafHash = keccak256(abi.encodePacked(receipt.receiptHash));
        return MerkleProof.verify(proof, merkleRoot, leafHash);
    }
}
