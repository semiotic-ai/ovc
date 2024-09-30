// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./utils/Pairing.sol";
import "./utils/MerkleProof.sol";
import "./utils/PatriciaTree.sol";

contract ReceiptProof {
    using Pairing for Pairing.G1Point;

    struct Receipt {
        // Define the structure of your Receipt here
        // This is a placeholder and should be replaced with later implementation
        bytes data;
    }

    struct ReceiptOpeningProof {
        Receipt receipt;
        bytes32[] inclusionProof;
    }

    function getIdxInBlock(Receipt memory receipt, Receipt[] memory leaves) public pure returns (uint256) {
        for (uint256 i = 0; i < leaves.length; i++) {
            if (keccak256(abi.encode(receipt)) == keccak256(abi.encode(leaves[i]))) {
                return i;
            }
        }
        revert("Receipt not found in leaves");
    }

    function getProof(Receipt memory receipt, Receipt[] memory leaves) public view returns (bytes32[] memory) {
        PatriciaTree.Tree memory tree = buildFromReceipts(leaves);
        uint256 receiptIdx = getIdxInBlock(receipt, leaves);
        return tree.getProof(abi.encode(receiptIdx));
    }

    function newOpeningProof(Receipt memory receipt, Receipt[] memory witness)
        public
        view
        returns (ReceiptOpeningProof memory)
    {
        bytes32[] memory inclusionProof = getProof(receipt, witness);
        return ReceiptOpeningProof(receipt, inclusionProof);
    }

    function verify(
        ReceiptOpeningProof memory self,
        Pairing.G1Point memory commitmentKey,
        bytes memory commitmentBytes,
        uint256 disagreementIdx,
        bytes32 rootHash
    ) public view returns (bool) {
        // Check that receipt opening the commitment is correct
        bytes memory receiptsBytes = encodeReceipt(self.receipt);
        uint256 hashedReceipt = uint256(keccak256(receiptsBytes));
        Pairing.G1Point memory commitment = commitmentKey.mul(hashedReceipt);
        bytes memory serializedCommitmentBytes = serializeG1Point(commitment);

        if (!bytesEqual(commitmentBytes, serializedCommitmentBytes)) {
            return false;
        }

        // Check that inclusion proof is valid with computed commitment
        bool validProof =
            MerkleProof.verify(self.inclusionProof, rootHash, keccak256(serializedCommitmentBytes), disagreementIdx);

        if (!validProof) {
            return false;
        }

        // Check that proof is valid receipt at leaf in opening proof matches claimed receipt
        bytes memory encodedReceipt = encodeReceiptWithBloom(self.receipt);
        bytes32 leafBytes = self.inclusionProof[self.inclusionProof.length - 1];

        return keccak256(encodedReceipt) == leafBytes;
    }

    function buildFromReceipts(Receipt[] memory receipts) internal pure returns (PatriciaTree.Tree memory) {
        PatriciaTree.Tree memory tree;
        for (uint256 i = 0; i < receipts.length; i++) {
            bytes memory key = abi.encode(i);
            bytes memory value = encodeReceiptWithBloom(receipts[i]);
            PatriciaTree.insert(tree, key, value);
        }
        return tree;
    }

    // Helper functions

    function encodeReceipt(Receipt memory receipt) internal pure returns (bytes memory) {
        // Implement the encoding of your Receipt structure
        // This is a placeholder and should be replaced with later implementation
        return receipt.data;
    }

    function encodeReceiptWithBloom(Receipt memory receipt) internal pure returns (bytes memory) {
        // Implement the encoding of your Receipt with Bloom filter
        // This is a placeholder and should be replaced with later implementation
        return receipt.data;
    }

    function serializeG1Point(Pairing.G1Point memory point) internal pure returns (bytes memory) {
        return abi.encodePacked(point.X, point.Y);
    }

    function bytesEqual(bytes memory a, bytes memory b) internal pure returns (bool) {
        return keccak256(a) == keccak256(b);
    }
}
